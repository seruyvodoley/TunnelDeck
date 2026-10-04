import AppKit
import Foundation
import SwiftUI

@MainActor
final class HomeAccessController:ObservableObject{
    @Published private(set)var network:HomeNetwork?
    @Published private(set)var devices:[HomeDevice]=[]
    @Published private(set)var snapshot=HomeNetworkSnapshot()
    @Published private(set)var lastDiscovery:Date?
    @Published private(set)var isRefreshing=false
    @Published private(set)var errorMessage:String?
    @Published private(set)var profiles:[LocalProfile]=[]
    private let store:InfrastructureStore?
    private let discovery:HomeDiscoveryService
    private var refreshTask:Task<Void,Never>?
    init(store:InfrastructureStore?=try? InfrastructureStore(),discovery:HomeDiscoveryService=HomeDiscoveryService()){self.store=store;self.discovery=discovery;profiles=ProfileStore.list(in:ProfileStore.homeAccessURL);Task{await load()}}
    func load()async{do{network=try await store?.activeHomeNetwork();devices=try await store?.homeDevices() ?? [];profiles=ProfileStore.list(in:ProfileStore.homeAccessURL);errorMessage=nil}catch{errorMessage=SecretRedactor.redact(error.localizedDescription)}}
    func saveNetwork(name:String,cidr:String,routerIP:String,notes:String)async{let now=Date(),value=HomeNetwork(id:network?.id ?? UUID(),name:name.trimmingCharacters(in:.whitespacesAndNewlines),cidr:cidr.trimmingCharacters(in:.whitespacesAndNewlines),routerIP:routerIP.trimmingCharacters(in:.whitespacesAndNewlines),notes:notes,createdAt:network?.createdAt ?? now,updatedAt:now);do{try await store?.save(homeNetwork:value);network=value;errorMessage=nil}catch{errorMessage=SecretRedactor.redact(error.localizedDescription)}}
    func refresh()async{
        guard refreshTask==nil else{return};isRefreshing=true
        let configuration=network
        refreshTask=Task{[weak self,discovery] in
            guard let self else{return}
            do{let(resultSnapshot,records)=try await discovery.discover(configuration:configuration);try Task.checkCancellation();await self.apply(snapshot:resultSnapshot,records:records)}
            catch is CancellationError{}
            catch{self.present(error)}
        }
        await refreshTask?.value;refreshTask=nil;isRefreshing=false
    }
    func stop()async{refreshTask?.cancel();refreshTask=nil;isRefreshing=false;await discovery.cancel()}
    private func apply(snapshot newSnapshot:HomeNetworkSnapshot,records:[HomeDiscoveryRecord])async{
        let now=Date();var updated=devices.map{device in var value=device;value.status=HomePresence.status(lastSeen:value.lastSeen,now:now,homeMode:newSnapshot.mode);return value}
        var observedIDs=Set<UUID>()
        for record in records{
            let mac=HomeDeviceIdentity.normalizedMAC(record.mac),id=HomeDeviceIdentity.stableID(mac:mac,ip:record.ip,hostname:record.hostname)
            let index=updated.firstIndex(where:{mac != nil && HomeDeviceIdentity.normalizedMAC($0.macAddress)==mac}) ?? updated.firstIndex(where:{$0.id==id})
            let device=HomeDeviceReconciler.merge(existing:index.map{updated[$0]},record:record,now:now)
            let observation=HomeDeviceObservation(deviceID:device.id,timestamp:now,status:.online,evidence:record.evidence,ip:record.ip,source:record.source)
            do{try await store?.save(homeDevice:device,observation:observation)}catch{errorMessage=SecretRedactor.redact(error.localizedDescription)}
            if let index{updated[index]=device}else{updated.append(device)}
            observedIDs.insert(device.id)
        }
        for device in updated where !observedIDs.contains(device.id){try? await store?.save(homeDevice:device)}
        snapshot=newSnapshot;devices=updated.sorted{($0.isPinned ? 0:1,$0.displayName.lowercased()) < ($1.isPinned ? 0:1,$1.displayName.lowercased())};lastDiscovery=now;errorMessage=nil
    }
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
