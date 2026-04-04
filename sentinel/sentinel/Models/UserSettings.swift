import Foundation
import Combine

class UserSettings: ObservableObject {
    private let defaults: UserDefaults

    @Published var autoConnect: Bool {
        didSet { defaults.set(autoConnect, forKey: "autoConnect") }
    }
    @Published var filterNoise: Bool {
        didSet { defaults.set(filterNoise, forKey: "filterNoise") }
    }
    @Published var retentionDays: Int {
        didSet { defaults.set(retentionDays, forKey: "retentionDays") }
    }

    init() {
        let defaults = AppGroupConfig.sharedDefaults
        self.defaults = defaults
        self.autoConnect = defaults.bool(forKey: "autoConnect")
        self.filterNoise = defaults.object(forKey: "filterNoise") as? Bool ?? true
        self.retentionDays = defaults.object(forKey: "retentionDays") as? Int ?? 30
    }
}
