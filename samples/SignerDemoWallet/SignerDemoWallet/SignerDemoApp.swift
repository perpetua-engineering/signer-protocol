//
//  SignerDemoApp.swift
//  SignerDemoWallet
//
//  Minimal third-party wallet demonstrating the Cryptograph Signer Protocol
//  (CR-1277). Plays the integrator role end to end: pair over a Universal
//  Link, receive the domain-bound callback, request EVM signatures approved
//  on the user's Apple Watch.
//
//  Spec: https://cryptograph.watch/signer-protocol
//

import SwiftUI

@main
struct SignerDemoApp: App {
    @StateObject private var model = DemoWalletModel()

    var body: some Scene {
        WindowGroup {
            DemoWalletView()
                .environmentObject(model)
                // Universal Link callbacks from Cryptograph arrive here.
                .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in
                    if let url = activity.webpageURL {
                        model.handleCallback(url)
                    }
                }
                // Custom-scheme/dev-time delivery (never carries real
                // responses in production — see spec §2.2).
                .onOpenURL { url in
                    model.handleCallback(url)
                }
        }
    }
}
