import UIKit
import AMSMB2

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        let _ = SMB2Manager(
            url: URL(string: "smb://127.0.0.1")!,
            credential: URLCredential(user: "test", password: "test", persistence: .none)
        )
        return true
    }
}
