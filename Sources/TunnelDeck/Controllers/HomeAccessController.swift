import AppKit
import Foundation
import SwiftUI

@MainActor
final class HomeAccessController:ObservableObject{
    @Published private(set)var network:HomeNetwork?
    @Published private(set)var devices:[HomeDevice]=[]
    @Published private(set)var snapshot=HomeNetworkSnapshot()
    @Published private(set)var lastDiscovery:Date?
    @Published private(set)var diagnostics=HomeDiscoveryDiagnostics()
    @Published private(set)var routerState:HomeRouterState = .notConfigured
    @Published private(set)var routerProviderName="TP-Link Archer AX18"
    @Published private(set)var routerLastSync:Date?
    @Published private(set)var routerAddress=UserDefaults.standard.string(forKey:"home-router-address") ?? ""
    @Published private(set)var routerUsername=UserDefaults.standard.string(forKey:"home-router-username") ?? ""
    @Published private(set)var isRefreshing=false
    @Published private(set)var errorMessage:String?
    @Published private(set)var profiles:[LocalProfile]=[]
    private let store:InfrastructureStore?
    private let discovery:HomeDiscoveryService
    private let routerProvider:any RouterClientInventoryProvider
    private var refreshTask:Task<Void,Never>?
    init(store:InfrastructureStore?=try? InfrastructureStore(),discovery:HomeDiscoveryService=HomeDiscoveryService(),routerProvider:any RouterClientInventoryProvider=TPLinkArcherAX18Provider()){self.store=store;self.discovery=discovery;self.routerProvider=routerProvider;profiles=ProfileStore.list(in:ProfileStore.homeAccessURL);Task{await load()}}
    func load()async{do{network=try await store?.activeHomeNetwork();devices=try await store?.homeDevices() ?? [];profiles=ProfileStore.list(in:ProfileStore.homeAccessURL);errorMessage=nil}catch{errorMessage=SecretRedactor.redact(error.localizedDescription)}}
    func saveNetwork(name:String,cidr:String,routerIP:String,notes:String)async{let now=Date(),value=HomeNetwork(id:network?.id ?? UUID(),name:name.trimmingCharacters(in:.whitespacesAndNewlines),cidr:cidr.trimmingCharacters(in:.whitespacesAndNewlines),routerIP:routerIP.trimmingCharacters(in:.whitespacesAndNewlines),notes:notes,createdAt:network?.createdAt ?? now,updatedAt:now);do{try await store?.save(homeNetwork:value);network=value;errorMessage=nil}catch{errorMessage=SecretRedactor.redact(error.localizedDescription)}}
    func refresh()async{
        guard refreshTask==nil else{return};isRefreshing=true
        let configuration=network
        refreshTask=Task{[weak self,discovery,routerProvider] in
            guard let self else{return}
            var routerRecords:[HomeDiscoveryRecord]=[]
            if !self.routerAddress.isEmpty,let password=KeychainService.load(account:"home-router-password"),!password.isEmpty{
                do{let clients: [RouterClientRecord];if self.routerState == .connected{do{clients=try await routerProvider.clients()}catch HomeRouterProviderError.authenticationRequired{_ = try await routerProvider.connect(address:self.routerAddress,username:self.routerUsername.nonEmptyValue,password:password);clients=try await routerProvider.clients()}}else{_ = try await routerProvider.connect(address:self.routerAddress,username:self.routerUsername.nonEmptyValue,password:password);clients=try await routerProvider.clients()};routerRecords=clients.flatMap{value in value.sources.map{source in HomeDiscoveryRecord(ip:value.ipv4 ?? value.ipv6 ?? "",mac:value.mac,hostname:value.hostname,source:source,evidence:value.online == true ? "Connected in TP-Link router client table":"Known to TP-Link router",routerDisplayName:value.displayName,connectionType:value.connectionType,online:source == .routerDHCP ? nil:value.online)}};if let routerIP=configuration?.routerIP.nonEmptyValue,!routerRecords.contains(where:{$0.ip==routerIP}){routerRecords.append(HomeDiscoveryRecord(ip:routerIP,mac:nil,hostname:nil,source:.routerClient,evidence:"Authenticated router inventory source",routerDisplayName:"Home Router",connectionType:.ethernet,online:true))};self.routerState = .connected;self.routerLastSync=Date()}
                catch HomeRouterProviderError.authenticationRequired{await routerProvider.disconnect();self.routerState = .authenticationRequired}
                catch HomeRouterProviderError.authenticationFailed{self.routerState = .authenticationRequired}
                catch{self.routerState = .unavailable}
            }else if !self.routerAddress.isEmpty{self.routerState = .authenticationRequired}else{self.routerState = .notConfigured}
            do{let(resultSnapshot,records,resultDiagnostics)=try await discovery.discover(configuration:configuration,routerRecords:routerRecords);try Task.checkCancellation();await self.apply(snapshot:resultSnapshot,records:records,diagnostics:resultDiagnostics)}
            catch is CancellationError{}
            catch{self.present(error)}
        }
        await refreshTask?.value;refreshTask=nil;isRefreshing=false
    }
    func stop()async{refreshTask?.cancel();refreshTask=nil;isRefreshing=false;await discovery.cancel()}
    private func apply(snapshot newSnapshot:HomeNetworkSnapshot,records:[HomeDiscoveryRecord],diagnostics newDiagnostics:HomeDiscoveryDiagnostics)async{
        let now=Date();var updated=devices.map{device in var value=device;value.status=HomePresence.status(lastSeen:value.lastSeen,now:now,homeMode:newSnapshot.mode);return value}
        var observedIDs=Set<UUID>()
        for record in records{
            let mac=HomeDeviceIdentity.normalizedMAC(record.mac),id=HomeDeviceIdentity.stableID(mac:mac,ip:record.ip,hostname:record.hostname)
            let index=updated.firstIndex(where:{mac != nil && HomeDeviceIdentity.normalizedMAC($0.macAddress)==mac}) ?? updated.firstIndex(where:{$0.id==id})
            let device=HomeDeviceReconciler.merge(existing:index.map{updated[$0]},record:record,now:now)
            let observedStatus:HomeDeviceReachability=record.online == true || record.source == .arp || record.source == .ndp ? .online:.unknown
            let observation=HomeDeviceObservation(deviceID:device.id,timestamp:now,status:observedStatus,evidence:record.evidence,ip:record.ip.nonEmptyValue,source:record.source)
            do{try await store?.save(homeDevice:device,observation:observation)}catch{errorMessage=SecretRedactor.redact(error.localizedDescription)}
            if let index{updated[index]=device}else{updated.append(device)}
            observedIDs.insert(device.id)
        }
        for device in updated where !observedIDs.contains(device.id){try? await store?.save(homeDevice:device)}
        snapshot=newSnapshot;diagnostics=newDiagnostics;devices=updated.sorted{($0.isPinned ? 0:1,$0.displayName.lowercased()) < ($1.isPinned ? 0:1,$1.displayName.lowercased())};lastDiscovery=now;errorMessage=nil
    }
    func saveRouterIntegration(address:String,username:String,password:String)async{let clean=address.trimmingCharacters(in:.whitespacesAndNewlines);guard !clean.isEmpty else{errorMessage="Router address is required.";return};do{if !password.isEmpty{try KeychainService.save(password,account:"home-router-password")};UserDefaults.standard.set(clean,forKey:"home-router-address");UserDefaults.standard.set(username,forKey:"home-router-username");routerAddress=clean;routerUsername=username;await refresh()}catch{present(error)}}
    func testRouterConnection(address:String,username:String,password:String)async{do{let secret=password.isEmpty ? KeychainService.load(account:"home-router-password") ?? "":password;_ = try await routerProvider.connect(address:address,username:username.nonEmptyValue,password:secret);_ = try await routerProvider.clients();routerState = .connected;errorMessage=nil;await routerProvider.disconnect()}catch HomeRouterProviderError.authenticationRequired{routerState = .authenticationRequired;errorMessage="Router authentication is required."}catch HomeRouterProviderError.authenticationFailed{routerState = .authenticationRequired;errorMessage="Router authentication failed."}catch{routerState = .unavailable;present(error)}}
    func forgetRouterCredentials()async{KeychainService.delete(account:"home-router-password");await routerProvider.disconnect();routerState=routerAddress.isEmpty ? .notConfigured:.authenticationRequired}
    func saveDevice(_ value:HomeDevice)async{var device=value;device.nameIsManual=true;device.typeIsManual=true;device.discoverySources.insert(.manual);do{try await store?.save(homeDevice:device);await load()}catch{errorMessage=SecretRedactor.redact(error.localizedDescription)}}
    func addManual(name:String,type:HomeDeviceType,ip:String,mac:String,hostname:String,notes:String)async{let normalized=HomeDeviceIdentity.normalizedMAC(mac),now=Date(),id=HomeDeviceIdentity.stableID(mac:normalized,manualID:UUID(),ip:ip.nonEmptyValue,hostname:hostname.nonEmptyValue),device=HomeDevice(id:id,displayName:name,hostname:hostname.nonEmptyValue,ipv4:ip.contains(":") ? nil:ip.nonEmptyValue,ipv6:ip.contains(":") ? ip:nil,macAddress:normalized,vendor:nil,type:type,customType:nil,status:.unknown,lastSeen:nil,firstSeen:now,discoverySources:[.manual],notes:notes.nonEmptyValue,nameIsManual:true,typeIsManual:true);await saveDevice(device)}
    func delete(_ id:UUID)async{do{try await store?.deleteHomeDevice(id);devices.removeAll{$0.id==id}}catch{errorMessage=SecretRedactor.redact(error.localizedDescription)}}
    func observations(for id:UUID)async->[HomeDeviceObservation]{(try? await store?.homeObservations(deviceID:id,since:Date().addingTimeInterval(-2_592_000))) ?? []}
    func merge(source:UUID,into destination:UUID)async{guard let sourceDevice=devices.first(where:{$0.id==source}),var target=devices.first(where:{$0.id==destination})else{return};target.lastSeen=max(target.lastSeen ?? .distantPast,sourceDevice.lastSeen ?? .distantPast);target.firstSeen=min(target.firstSeen,sourceDevice.firstSeen);target.discoverySources.formUnion(sourceDevice.discoverySources);target.ipv4=target.ipv4 ?? sourceDevice.ipv4;target.ipv6=target.ipv6 ?? sourceDevice.ipv6;target.macAddress=target.macAddress ?? sourceDevice.macAddress;do{try await store?.save(homeDevice:target);try await store?.mergeHomeDevices(source:source, destination:destination);await load()}catch{errorMessage=SecretRedactor.redact(error.localizedDescription)}}
    func importProfile(from url:URL)async{do{_ = try ProfileStore.importHomeAccess(from:url);profiles=ProfileStore.list(in:ProfileStore.homeAccessURL);errorMessage=nil}catch{errorMessage=SecretRedactor.redact(error.localizedDescription)}}
    func renameProfile(_ profile:LocalProfile,to name:String){do{_ = try ProfileStore.rename(profile,name:name,in:ProfileStore.homeAccessURL);profiles=ProfileStore.list(in:ProfileStore.homeAccessURL)}catch{errorMessage=SecretRedactor.redact(error.localizedDescription)}}
    func deleteProfile(_ profile:LocalProfile){do{try ProfileStore.delete(profile,within:ProfileStore.homeAccessURL);profiles=ProfileStore.list(in:ProfileStore.homeAccessURL)}catch{errorMessage=SecretRedactor.redact(error.localizedDescription)}}
    private func present(_ error:Error){errorMessage=SecretRedactor.redact(error.localizedDescription)}
}

private extension String{var nonEmptyValue:String?{let value=trimmingCharacters(in:.whitespacesAndNewlines);return value.isEmpty ? nil:value}}
