//
//  Network.swift
//  bplayer
//
//  Created by Gabriel Rodrigues on 20/07/21.
//

import Foundation
import Alamofire
import AVFoundation

class Network {
    
    static let shared = Network()
    
    private let manager = Alamofire.Session()
    
    private func binaryQuery(challenge: String, sessionToken: String) -> String {
        return #"""
            {"query":"{\n drm_license(session_token: \"\#(sessionToken)\",
            license_challenge: \"\#(challenge)\") { ...on license{license}...on error{error code message}}}","variables":{}}
        """#
    }
    
    func getBinary(_ loadingRequest: AVAssetResourceLoadingRequest,
                   userToken: String,
                   sessionToken: String,
                   body: String,
                   completion: @escaping (Data) -> ()) {
        
        let url = URL(string: "http://hermes.brasilparalelo.com.br/api")!
        
        var request = URLRequest(url: url)
        
        request.httpMethod = HTTPMethod.post.rawValue
        request.setValue("application/json", forHTTPHeaderField: "content-type")
        request.setValue("Bearer \(userToken)", forHTTPHeaderField: "Authorization")
        request.httpBody = binaryQuery(challenge: body, sessionToken: sessionToken).data(using: .utf8)!
        
        manager.request(request).responseData { response in
            print("response: \(String(data: response.data!, encoding: .utf8))")
            guard let json = try? JSONSerialization.jsonObject(with: response.data!, options: []) as? [String:Any],
                  let dataDict = json["data"] as? [String:Any],
                  let drmDict = dataDict["drm_license"] as? [String:Any],
                  let license = drmDict["license"] as? String else {
                print(#function, "Unable to get license from the server.")
                return
            }
            
            completion(Data(base64Encoded: license)!)
        }
    }
}


