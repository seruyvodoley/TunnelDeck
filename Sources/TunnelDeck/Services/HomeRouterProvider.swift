import CCommonCrypto
import CryptoKit
import Foundation
import Security

struct RouterClientRecord:Sendable,Equatable{
    let mac:String;var ipv4:String?;var ipv6:String?;var hostname:String?;var displayName:String?;var connectionType:HomeConnectionType;var online:Bool?;var leaseExpires:Date?;var sources:Set<HomeDiscoverySource>
}

struct HomeRouterInfo:Sendable,Equatable{let provider:String;let hardwareVersion:String?;let firmwareVersion:String?}

protocol RouterClientInventoryProvider:Sendable{
    func connect(address:String,username:String?,password:String)async throws->HomeRouterInfo
    func clients()async throws->[RouterClientRecord]
    func disconnect()async
}

enum HomeRouterProviderError:LocalizedError,Equatable{
    case invalidAddress,authenticationRequired,authenticationFailed,unsupportedFirmware,malformedResponse,writeOperationRejected,unavailable
    var errorDescription:String?{switch self{case .invalidAddress:"Invalid router address.";case .authenticationRequired:"Router authentication is required.";case .authenticationFailed:"Router authentication failed.";case .unsupportedFirmware:"This router firmware protocol is not supported safely.";case .malformedResponse:"The router returned a malformed response.";case .writeOperationRejected:"A non-read router operation was rejected before transmission.";case .unavailable:"The router is unavailable."}}
}

protocol RouterHTTPTransport:Sendable{func post(url:URL,body:Data)async throws->Data}
final class URLSessionRouterTransport:RouterHTTPTransport,@unchecked Sendable{
    private let session:URLSession
    init(){let configuration=URLSessionConfiguration.ephemeral;configuration.httpCookieStorage=nil;configuration.urlCredentialStorage=nil;configuration.requestCachePolicy = .reloadIgnoringLocalCacheData;session=URLSession(configuration:configuration)}
    func post(url:URL,body:Data)async throws->Data{var request=URLRequest(url:url);request.httpMethod="POST";request.httpBody=body;request.timeoutInterval=12;request.setValue("application/x-www-form-urlencoded",forHTTPHeaderField:"Content-Type");request.setValue("no-cache",forHTTPHeaderField:"Cache-Control");let(data,response)=try await session.data(for:request);guard let http=response as? HTTPURLResponse,(200..<300).contains(http.statusCode)else{throw HomeRouterProviderError.unavailable};return data}
}

actor TPLinkArcherAX18Provider:RouterClientInventoryProvider{
    private enum ReadAction:String{case activeClients="loadDevice",dhcpLeases="load"}
    private let transport:any RouterHTTPTransport
    private var baseURL:URL?;private var token:String?;private var crypto:TPLinkCryptoSession?;private var info=HomeRouterInfo(provider:"TP-Link Archer AX18",hardwareVersion:nil,firmwareVersion:nil)
    init(transport:any RouterHTTPTransport=URLSessionRouterTransport()){self.transport=transport}

    func connect(address:String,username:String?,password:String)async throws->HomeRouterInfo{
        guard let base=Self.validBaseURL(address)else{throw HomeRouterProviderError.invalidAddress}
        baseURL=base;token=nil;crypto=nil
        let config=try await plain(path:"/device_config?form=config",parameters:["operation":"read"])
        let certifications=Self.strings(config["certification"])
        guard certifications.contains("SG CLS L1 STAGE2")else{throw HomeRouterProviderError.unsupportedFirmware}
        let auth=try await plain(path:"/login?form=auth",parameters:["operation":"read"]),keys=try await plain(path:"/login?form=keys",parameters:["operation":"read"])
        guard let sequence=Self.int(auth["seq"]),let authKey=Self.stringArray(auth["key"]),authKey.count==2,let passwordKey=Self.stringArray(keys["password"]),passwordKey.count==2 else{throw HomeRouterProviderError.malformedResponse}
        let session=try TPLinkCryptoSession(password:password,sequence:sequence,authModulus:authKey[0],authExponent:authKey[1])
        let encryptedPassword=try TPLinkRSA.encryptHex(Data(password.utf8),modulus:passwordKey[0],exponent:passwordKey[1])
        let login=try await encrypted(path:"/login?form=login",parameters:["operation":"login","password":encryptedPassword],session:session,includeAESKey:true,token:"")
        guard let stok=Self.string(login["stok"]),!stok.isEmpty else{throw HomeRouterProviderError.authenticationFailed}
        token=stok;crypto=session
        if let firmware=Self.dictionary(config["firmware"]){info=HomeRouterInfo(provider:"TP-Link Archer AX18",hardwareVersion:Self.string(firmware["hardwareVersion"]),firmwareVersion:Self.string(firmware["firmwareVersion"]))}
        _=username // Current AX18 firmware uses password-only local authentication.
        return info
    }

    func clients()async throws->[RouterClientRecord]{
        guard let token,let session=crypto else{throw HomeRouterProviderError.authenticationRequired}
        do{
            let active=try await read(.activeClients,path:"/admin/smart_network?form=game_accelerator",session:session,token:token)
            let leases=try await read(.dhcpLeases,path:"/admin/dhcps?form=client",session:session,token:token)
            return Self.merge(active:Self.parseActive(active),leases:Self.parseDHCP(leases))
        }catch HomeRouterProviderError.authenticationRequired{self.token=nil;crypto=nil;throw HomeRouterProviderError.authenticationRequired}
    }
    func disconnect(){token=nil;crypto=nil}

    private func read(_ action:ReadAction,path:String,session:TPLinkCryptoSession,token:String)async throws->[String:Any]{
        let parameters:[String:String]=["operation":action.rawValue]
        guard Self.allowed(path:path,parameters:parameters)else{throw HomeRouterProviderError.writeOperationRejected}
        return try await encrypted(path:path,parameters:parameters,session:session,includeAESKey:false,token:token)
    }
    static func allowed(path:String,parameters:[String:String])->Bool{
        let exact:[String:Set<String>]=["/admin/smart_network?form=game_accelerator":["loadDevice"],"/admin/dhcps?form=client":["load"]]
        guard let operations=exact[path],let operation=parameters["operation"],operations.contains(operation),parameters.count==1 else{return false}
        return true
    }

    private func plain(path:String,parameters:[String:String])async throws->[String:Any]{
        guard let baseURL else{throw HomeRouterProviderError.invalidAddress};let url=try endpoint(baseURL:baseURL,token:"",path:path),data=try await transport.post(url:url,body:Self.form(parameters));return try Self.unwrap(data,decrypt:nil)
    }
    private func encrypted(path:String,parameters:[String:String],session:TPLinkCryptoSession,includeAESKey:Bool,token:String)async throws->[String:Any]{
        guard let baseURL else{throw HomeRouterProviderError.invalidAddress};let payload=Self.formString(parameters),sealed=try session.seal(payload,includeAESKey:includeAESKey),url=try endpoint(baseURL:baseURL,token:token,path:path),data=try await transport.post(url:url,body:Self.form(["sign":sealed.sign,"data":sealed.data]));return try Self.unwrap(data,decrypt:session)
    }
    private func endpoint(baseURL:URL,token:String,path:String)throws->URL{guard let value=URL(string:"/cgi-bin/luci/;stok=\(token)\(path)",relativeTo:baseURL)?.absoluteURL else{throw HomeRouterProviderError.invalidAddress};return value}
    private static func validBaseURL(_ value:String)->URL?{let raw=value.trimmingCharacters(in:.whitespacesAndNewlines),candidate=raw.contains("://") ? raw:"http://\(raw)";guard let url=URL(string:candidate),["http","https"].contains(url.scheme?.lowercased() ?? ""),url.user==nil,url.password==nil,url.query==nil,url.fragment==nil,url.host != nil else{return nil};return URL(string:"\(url.scheme!)://\(url.host!)\(url.port.map{":\($0)"} ?? "")/")}
    private static func unwrap(_ data:Data,decrypt:TPLinkCryptoSession?)throws->[String:Any]{guard let root=try JSONSerialization.jsonObject(with:data)as? [String:Any]else{throw HomeRouterProviderError.malformedResponse};if let success=root["success"]as? Bool,!success{let code=string(root["errorCode"]) ?? string(root["error"]);if code=="timeout" || code=="permission denied"{throw HomeRouterProviderError.authenticationRequired};throw HomeRouterProviderError.authenticationFailed};let payload:Any=root["data"] ?? root;if let encrypted=payload as? String,let decrypt{let clear=try decrypt.open(encrypted);guard let object=try JSONSerialization.jsonObject(with:Data(clear.utf8))as? [String:Any]else{throw HomeRouterProviderError.malformedResponse};return object};return payload as? [String:Any] ?? ["items":payload]}
    private static func form(_ values:[String:String])->Data{Data(formString(values).utf8)}
    private static func formString(_ values:[String:String])->String{values.keys.sorted().map{"\($0.urlFormEncoded)=\((values[$0] ?? "").urlFormEncoded)"}.joined(separator:"&")}
    private static func dictionary(_ value:Any?)->[String:Any]?{value as? [String:Any]};private static func string(_ value:Any?)->String?{value as? String};private static func int(_ value:Any?)->Int?{value as? Int ?? (value as? NSNumber)?.intValue};private static func stringArray(_ value:Any?)->[String]?{value as? [String]};private static func strings(_ value:Any?)->[String]{value as? [String] ?? []}
    private static func arrays(in value:Any)->[[[String:Any]]]{if let rows=value as? [[String:Any]]{return[rows]};if let object=value as? [String:Any]{return object.values.flatMap{arrays(in:$0)}};if let list=value as? [Any]{return list.flatMap{arrays(in:$0)}};return[]}
    static func parseActive(_ object:[String:Any])->[RouterClientRecord]{arrays(in:object).flatMap{$0}.compactMap{row in guard let mac=HomeDeviceIdentity.normalizedMAC(string(row["mac"]) ?? string(row["macaddr"]))else{return nil};let tag=(string(row["device_tag"]) ?? string(row["deviceTag"]) ?? string(row["conn_type"]) ?? "").lowercased(),connection:HomeConnectionType=tag.contains("wired") ? .ethernet:tag.contains("2g") ? .wifi24:tag.contains("5g") ? .wifi5:tag.contains("6g") ? .wifi6:.wifi;return RouterClientRecord(mac:mac,ipv4:string(row["ip"]) ?? string(row["ipaddr"]),hostname:string(row["hostname"]),displayName:string(row["device_name"]) ?? string(row["deviceName"]) ?? string(row["name"]),connectionType:connection,online:true,sources:[.routerClient,connection == .ethernet ? .routerWired:.routerWireless])}}
    static func parseDHCP(_ object:[String:Any])->[RouterClientRecord]{arrays(in:object).flatMap{$0}.compactMap{row in guard let mac=HomeDeviceIdentity.normalizedMAC(string(row["mac"]) ?? string(row["macaddr"]) ?? string(row["mac_address"]))else{return nil};return RouterClientRecord(mac:mac,ipv4:string(row["ip"]) ?? string(row["ipaddr"]) ?? string(row["assigned_ip"]),hostname:string(row["name"]) ?? string(row["hostname"]),displayName:nil,connectionType:.unknown,online:nil,leaseExpires:nil,sources:[.routerDHCP])}}
    static func merge(active:[RouterClientRecord],leases:[RouterClientRecord])->[RouterClientRecord]{var values=[String:RouterClientRecord]();for value in leases+active{if var old=values[value.mac]{old.ipv4=value.ipv4 ?? old.ipv4;old.ipv6=value.ipv6 ?? old.ipv6;old.hostname=value.hostname ?? old.hostname;old.displayName=value.displayName ?? old.displayName;if value.connectionType != .unknown{old.connectionType=value.connectionType};old.online=value.online ?? old.online;old.sources.formUnion(value.sources);values[value.mac]=old}else{values[value.mac]=value}};return values.values.sorted{$0.mac<$1.mac}}
}

private struct TPLinkCryptoSession:Sendable{
    let key:String;let iv:String;let sequence:Int;let hash:String;let authModulus:String;let authExponent:String
    init(password:String,sequence:Int,authModulus:String,authExponent:String)throws{key=Self.digits(16);iv=Self.digits(16);self.sequence=sequence;hash=SHA256.hash(data:Data("admin\(password)".utf8)).map{String(format:"%02x",$0)}.joined();self.authModulus=authModulus;self.authExponent=authExponent}
    func seal(_ clear:String,includeAESKey:Bool)throws->(sign:String,data:String){let encrypted=try Self.aes(Data(clear.utf8),key:key,iv:iv,operation:CCOperation(kCCEncrypt)).base64EncodedString(),prefix=includeAESKey ? "k=\(key)&i=\(iv)&":"",signature="\(prefix)h=\(hash)&s=\(sequence+encrypted.count)";return(try TPLinkRSA.encryptHex(Data(signature.utf8),modulus:authModulus,exponent:authExponent),encrypted)}
    func open(_ encrypted:String)throws->String{guard let data=Data(base64Encoded:encrypted)else{throw HomeRouterProviderError.malformedResponse};return String(decoding:try Self.aes(data,key:key,iv:iv,operation:CCOperation(kCCDecrypt)),as:UTF8.self)}
    private static func digits(_ count:Int)->String{String((0..<count).map{_ in Character(String(Int.random(in:0...9)))})}
    private static func aes(_ input:Data,key:String,iv:String,operation:CCOperation)throws->Data{let outputCapacity=input.count+kCCBlockSizeAES128;var output=Data(count:outputCapacity),moved=0;let status=output.withUnsafeMutableBytes{out in input.withUnsafeBytes{src in key.withCString{keyPtr in iv.withCString{ivPtr in CCCrypt(operation,CCAlgorithm(kCCAlgorithmAES),CCOptions(kCCOptionPKCS7Padding),keyPtr,kCCKeySizeAES128,ivPtr,src.baseAddress,input.count,out.baseAddress,outputCapacity,&moved)}}}};guard status==kCCSuccess else{throw HomeRouterProviderError.unsupportedFirmware};output.count=moved;return output}
}

private enum TPLinkRSA{
    static func encryptHex(_ data:Data,modulus:String,exponent:String)throws->String{let modulusData=try hex(modulus),exponentData=try hex(exponent),keyData=derSequence(derInteger(modulusData)+derInteger(exponentData)),attributes:[CFString:Any]=[kSecAttrKeyType:kSecAttrKeyTypeRSA,kSecAttrKeyClass:kSecAttrKeyClassPublic,kSecAttrKeySizeInBits:modulusData.count*8];var error:Unmanaged<CFError>?;guard let key=SecKeyCreateWithData(keyData as CFData,attributes as CFDictionary,&error)else{if let error{throw error.takeRetainedValue()};throw HomeRouterProviderError.unsupportedFirmware};let algorithm:SecKeyAlgorithm = .rsaEncryptionOAEPSHA1;guard SecKeyIsAlgorithmSupported(key,.encrypt,algorithm)else{throw HomeRouterProviderError.unsupportedFirmware};let chunk=max(1,SecKeyGetBlockSize(key)-42);var result="";for start in stride(from:0,to:data.count,by:chunk){let part=data.subdata(in:start..<min(start+chunk,data.count));guard let encrypted=SecKeyCreateEncryptedData(key,algorithm,part as CFData,&error)as Data? else{if let error{throw error.takeRetainedValue()};throw HomeRouterProviderError.unsupportedFirmware};result+=encrypted.map{String(format:"%02x",$0)}.joined()};return result}
    private static func hex(_ value:String)throws->Data{guard value.count%2==0 else{throw HomeRouterProviderError.malformedResponse};var data=Data();var index=value.startIndex;while index<value.endIndex{let end=value.index(index,offsetBy:2);guard let byte=UInt8(value[index..<end],radix:16)else{throw HomeRouterProviderError.malformedResponse};data.append(byte);index=end};return data}
    private static func derInteger(_ value:Data)->Data{let body=(value.first ?? 0)&0x80 != 0 ? Data([0])+value:value;return Data([0x02])+derLength(body.count)+body}
    private static func derSequence(_ value:Data)->Data{Data([0x30])+derLength(value.count)+value}
    private static func derLength(_ count:Int)->Data{if count<128{return Data([UInt8(count)])};let bytes=withUnsafeBytes(of:UInt32(count).bigEndian){Array($0).drop{ $0==0 }};return Data([0x80|UInt8(bytes.count)]+bytes)}
}

private extension String{var urlFormEncoded:String{addingPercentEncoding(withAllowedCharacters:CharacterSet.alphanumerics.union(CharacterSet(charactersIn:"-._~"))) ?? ""}}
