import Foundation
import CryptoKit
import CoreBluetooth
import UIKit
import BlackoutCore

/// Owns the one Engine. It starts as soon as the app process starts, if a group is set up, so it also runs when iOS
/// relaunches DarkProof in the background for Bluetooth (BleLink's restore identifiers), with no screen at all.
final class Mesh: ObservableObject {
    static let shared = Mesh()
    @Published private(set) var engine: Engine?

    /// Starts the mesh for the saved group, if there is one. Safe to call more than once.
    func startIfSetUp() {
        let d = UserDefaults.standard
        guard engine == nil, let code = GroupSecrets.shared.current, !code.isEmpty else { return }
        engine = Engine(name: d.string(forKey: "name") ?? "", code: code)
    }

    /// Starts the mesh right after setup. Bluetooth starts first; the Wi-Fi links (which ask for Local Network)
    /// only once the Bluetooth question is answered, so iOS asks one thing at a time.
    func start(name: String, code: String) {
        if engine == nil { engine = Engine(name: name, code: code, askInOrder: true) }
    }
}

/// State shared between the transports and the UI, like the Android MeshEngine.
final class Engine: ObservableObject {
    static let maxTtl = MeshRouter.maxTtl
    private static let handedOffMax = 2_000  // "Sent" labels remembered across restarts
    private static let maxPublic = 2_000     // Public messages kept on the phone; older ones are removed
    private static let week: Int64 = 7 * 24 * 3_600_000
    /// This group's messages and the Public channel's, oldest first, without blocked people and reported messages.
    @Published private(set) var messages: [Message] = []
    /// Every saved group's messages and the Public channel's, likewise; `Message.group` tells which group.
    @Published private(set) var allMessages: [Message] = []
    @Published private(set) var status: [String: String] = [:] // transport -> status line
    @Published private(set) var phones = 0        // other devices linked directly, each counted once
    @Published private(set) var bluetoothLinks = 0
    @Published private(set) var wifiLinks = 0
    @Published private(set) var wifiNetworkLinks = 0 // phones linked over a Wi-Fi network (WifiLink)
    @Published private(set) var radioLinked = false
    @Published private(set) var meshcoreLinked = false
    @Published private(set) var relaysLinked = 0     // internet relays connected right now (NostrLink)
    @Published private(set) var throughTor: Bool?    // "Connect through Tor": true when checked, false while waiting
    @Published private(set) var linkedNodes: Set<String> = [] // node ids linked directly right now
    @Published private(set) var name: String
    @Published private(set) var deliveries = Deliveries()  // who confirmed which message (spec/FORMAT.md, "Delivery receipts")
    @Published private(set) var handedOff: Set<String> = [] // ids of my messages given to a phone, radio or the relays
    /// A check-in waiting for its GPS fix (up to 10 s): the buttons show "Sending…" and stay disabled meanwhile.
    @Published private(set) var checkInSending: CheckIn?
    @Published private(set) var bluetooth = CBManagerState.unknown  // this phone's Bluetooth: off, not allowed…
    @Published private(set) var localNetworkDenied = false          // Local Network refused: no Wi-Fi links
    @Published private(set) var networkStarted = false              // the Wi-Fi links started (after the Bluetooth question)
    @Published private(set) var torSlow = false                     // "Connect through Tor" found no way out for 2 minutes
    private var torWaitingSince: Date?
    /// Marks this phone's own messages on this phone only (`Message.sender`); never sent: packets carry member ids.
    let deviceId: String
    /// The node id other phones see when they link (spec/FORMAT.md, "Link ids"): random, new at every app start,
    /// unrelated to member ids, so a phone seen over the air can't be matched to a person or followed across restarts.
    let linkId: String = {
        var b = [UInt8](repeating: 0, count: 6)
        _ = SecRandomCopyBytes(kSecRandomDefault, b.count, &b)
        return b.map { String(format: "%02x", $0) }.joined()
    }()
    let startedAt = Int64(Date().timeIntervalSince1970 * 1000)

    /// What a group's code opens (spec/DESIGN-v0.6-groups.md, "Keys"): introductions, new keys, and messages from phones not in yet.
    final class Door: @unchecked Sendable {
        let code: String, crypto: GroupCrypto, receipts: GroupCrypto, intros: GroupCrypto, rekeys: GroupCrypto, id: String
        init(_ code: String) {
            self.code = code; crypto = GroupCrypto(code: code); receipts = crypto.receipts(); intros = crypto.intros(); rekeys = crypto.rekeys()
            id = crypto.groupId()
        }
    }

    /// A saved group's keys (spec/FORMAT.md, "Encryption", "Delivery receipts", "Introductions"), this phone's member
    /// key there (Keychain), and the members' public keys this phone knows (`known`, guarded by `lock`).
    final class Keys: @unchecked Sendable {
        private var doors: (now: Door, old: [Door]) // lock
        private var state: (removedAt: (number: Int64, rank: Int)?, closed: Bool, rejoiningSince: Int64) = (nil, false, 0) // lock
        /// The door in use. It changes when someone is removed; the old ones stay a week, for removals that crossed.
        var door: Door { lock.withLock { doors.now } }
        var oldDoors: [Door] { lock.withLock { doors.old } }
        func setDoors(_ now: Door, old: [Door]) { lock.withLock { doors = (now, old) } }
        var code: String { door.code }
        var intros: GroupCrypto { door.intros }
        var rekeys: GroupCrypto { door.rekeys }
        /// This phone was removed from the group: that removal's epoch number and its maker's rank.
        var removedAt: (number: Int64, rank: Int)? { get { lock.withLock { state.removedAt } } set { lock.withLock { state.removedAt = newValue } } }
        var removed: Bool { removedAt != nil }
        /// This phone had been away past the weekly key and asked to come back (its new key is the request): since when, or 0.
        var rejoiningSince: Int64 { get { lock.withLock { state.rejoiningSince } } set { lock.withLock { state.rejoiningSince = newValue } } }
        var rejoining: Bool { rejoiningSince > 0 }
        /// How long after the week is up this phone makes the new key.
        let weeklyDelay = Int64.random(in: 0..<Keyring.maxDelayMs)
        /// Still joining or rejoining, and a removal came through this door: this invite no longer works.
        var closed: Bool { get { lock.withLock { state.closed } } set { lock.withLock { state.closed = newValue } } }
        /// Never changes for the group, even when its code does: member keys hang off it.
        let id: String
        /// The group's random epoch secrets. Empty while this phone is joining.
        let ring = Keyring()
        var joined: Bool { ring.currentOrNil != nil }
        /// Written with: the current epoch's keys, or the door's while joining.
        var group: GroupCrypto { ring.currentOrNil?.group ?? door.crypto }
        var receipts: GroupCrypto { ring.currentOrNil?.receipts ?? door.receipts }
        var members: [String] { ring.currentOrNil?.members ?? [] }
        let key: MemberKeys.SigningKey, pub: Data, me: String
        /// The HPKE keys other members seal new epoch secrets to: a new one every week.
        let encs: EncKeys
        var encPub: Data { encs.currentPub }
        var isPublic: Bool { code == GroupCrypto.publicCode }
        let lock = NSLock(), moveLock = NSLock()
        var known: [String: Known] = [:] // member id -> their keys and name
        let mine: MemberKey.Checker
        init(code: String) {
            let d = Door(code)
            doors = (d, [])
            id = Vault.get("origin.\(d.id)").flatMap { String(data: $0, encoding: .utf8) } ?? d.id
            key = MemberKeys.forGroup(id); pub = key.publicKey.compressedRepresentation; me = MemberKey.id(pub)
            encs = EncKeys(id)
            mine = MemberKey.Checker(pub)!
            #if DEBUG
            DebugLog.write("member keys: signing \(key.inChip ? "in the Secure Enclave" : "in the Keychain"), encryption \(encs.inChip ? "in the Secure Enclave" : "in the Keychain")")
            #endif
        }
        func sign(_ msg: Data) throws -> Data { try key.sign(msg) }
        func checker(_ id: String) -> MemberKey.Checker? { id == me ? mine : lock.withLock { known[id]?.checker } }
    }

    /// A member's public keys, from their introduction.
    /// Group id -> what was written before an admin let this phone in. Main thread.
    private var waitingToJoin: [String: [(text: String, photo: Data?)]] = [:]

    struct Known { let checker: MemberKey.Checker; let enc: Data?; let name: String; var encAt: Int64 = 0; var pq: Data? = nil }

    /// A packet opened with one of `Keys`: not shown before its signature is checked (spec "Signatures").
    private enum Seen {
        case msg(Message, Keys, GroupCrypto.Opened, Bool) // the last: from this phone's copy
        case receipt(Message, Keys, GroupCrypto.Opened)
        case intro(Keys, String, MemberKey.Checker, Data, String, Int64, Data?) // keys, member id, its key, encryption key, name, when, ML-KEM key
        case newKey(Keys, GroupCrypto.Opened, Rekey, String, Door) // keys, opened packet, rekey, packet id, the door it came through
        case forged                                       // an introduction that doesn't hold up
    }

    /// A message or receipt from a member whose public key isn't known yet; checked when the introduction comes.
    private struct Pending { let k: Keys; let sender: String; let o: GroupCrypto.Opened; let receipt: Message? }
    private var pending: [String: Pending] = [:] // main thread: packet id -> waiting
    private static let maxPending = 1_000, maxKnown = 500, introEvery: Int64 = 3 * 24 * 3_600_000
    private let keyLock = NSLock()
    private let knownLock = NSLock()
    private let rescanLock = NSLock(), rescanFlag = Flag() // new keys arriving together: one reading of the store
    private final class Flag { var on = false }
    private var keyCache: [String: Keys] = [:] // code -> keys: each derivation takes 32 MiB of scrypt, so only once
    private let cryptoLock = NSLock()          // guards the three below: read from the router's thread
    private var _active: Keys?                 // the group on screen
    private var _others: [Keys] = []           // the other saved groups: read, alerted and confirmed too
    private var _public: Keys?                 // the Public channel's
    private var keySet: (active: Keys?, others: [Keys], pub: Keys?) { cryptoLock.withLock { (_active, _others, _public) } }
    private var activeCode: String             // main thread: the group on screen, even while its keys are derived

    private let idsLock = NSLock()
    private var mine = Set<String>()       // ids of messages written on this phone; guarded by idsLock
    private var myReceipts = Set<String>() // ids of receipts written on this phone (they go up to the relays first); idsLock
    private var sentIds: RecentIds         // my messages already handed off, saved on the phone; idsLock
    private var receiptIds = RecentIds(max: 20_000) // receipt packets this phone can open, kept off LoRa; guarded by idsLock

    private let storeLock = NSLock()
    private var index: [String: StoreCap.Entry] = [:] // every stored packet, for the store cap; guarded by storeLock
    private var indexBytes = 0                        // storeLock
    private var allKeys = false                       // every saved group's key was tried on the whole store; storeLock
    private var compacting = false                    // storeLock
    private let work = DispatchQueue(label: "engine", qos: .userInitiated) // loading, keys and compaction, in order

    private var raw: [Message] = []          // main thread: every readable message, before moderation
    private var rawIds = Set<String>()       // main thread
    private var receiptMsgs: [String: Message] = [:] // main thread: opened receipts by packet id
    private var pendingAcks: [(id: String, key: Keys)] = [] // main thread: messages to confirm, with their group's keys
    private var firstAck: Int64 = 0, lastAck: Int64 = 0            // main thread

    private let store = PacketStore()
    private let history = PacketStore(file: "history.bin")
    private(set) var router: MeshRouter!
    private var ble: BleLink!
    private var mc: MultipeerLink!
    private(set) var lora: LoraLink!
    private(set) var meshcore: MeshCoreLink!
    private(set) var wifi: WifiLink!
    private(set) var nostr: NostrLink!

    /// Starts the transports at once; keys and stored messages are read in the background (no scrypt key
    /// derivation or store reading on the main thread), then published.
    init(name: String, code: String, askInOrder: Bool = false) {
        let d = UserDefaults.standard
        let upgrade = d.string(forKey: "device") != nil // this phone ran DarkProof before (a device id exists from then)
        if let id = d.string(forKey: "device") { deviceId = id } else {
            deviceId = String(UUID().uuidString.lowercased().prefix(12)) // same shape as Android ids, e.g. 7c0d995b-2c4
            d.set(deviceId, forKey: "device")
        }
        self.name = name
        activeCode = code
        if !d.bool(forKey: "v06") { // groups saved before v0.6 count as founded here (spec "Making the first epoch")
            let saved = upgrade ? Set(SavedGroups.all().map(\.code) + (GroupSecrets.shared.current.map { [$0] } ?? [])) : []
            GroupSecrets.shared.setFound(Array(Set(GroupSecrets.shared.found).union(saved)))
            d.set(true, forKey: "v06")
            for key in d.dictionaryRepresentation().keys where key.hasPrefix("introAt.") { d.removeObject(forKey: key) } // introductions now carry the encryption key
        }
        sentIds = RecentIds(max: Self.handedOffMax, d.stringArray(forKey: "handedOff") ?? [])
        handedOff = Set(sentIds.list)
        router = MeshRouter(send: { [weak self] peer, p in self?.route(peer, p) },
                            deliver: { [weak self] p in self?.onDeliver(p) },
                            minCipher: MeshRouter.minSealed, maxPerMinute: MeshRouter.linkPerMinute, unlimited: { $0 == NostrLink.peer })
        mc = MultipeerLink(nodeId: linkId, router: router) { [weak self] s in self?.setStatus("1-mc", s) }
        ble = BleLink(nodeId: linkId, router: router) { [weak self] s in self?.setStatus("2-ble", s) }
        lora = LoraLink(router: router) { [weak self] s in self?.setStatus("3-lora", s) }
        meshcore = MeshCoreLink(router: router) { [weak self] s in self?.setStatus("3b-meshcore", s) }
        wifi = WifiLink(nodeId: linkId, router: router) { [weak self] s in self?.setStatus("4-wifi", s) }
        nostr = NostrLink(router: router, viaTor: d.object(forKey: "tor") as? Bool ?? true, scopes: { [weak self] in self?.relayScopes() ?? [] },
                          onRelays: { [weak self] id in self?.markHandedOff(id) }) { [weak self] s in
            self?.setStatus("5-internet", s)
        }
        nostr.setSaver(Self.saver)
        if d.object(forKey: "internet") as? Bool ?? true { nostr.start() }
        #if DEBUG
        DebugLog.start()
        GroupSecrets.shared.noteForTests()
        BleLink.restoredHook = { DebugLog.write("bluetooth " + $0) }
        #endif
        ble.start()
        lora.start()
        meshcore.start()
        if askInOrder && CBManager.authorization == .notDetermined {
            afterBluetoothAnswer(tries: 240) { [weak self] in self?.startNetwork() }
        } else {
            startNetwork()
        }
        work.async { self.startUp(code) }
    }

    /// Apple peer-to-peer and Wi-Fi networks: both make iOS ask for Local Network.
    private func startNetwork() {
        mc.start()
        if wifiWanted { wifi.start() }
        networkStarted = true
    }

    /// Waits (at most `tries` × 0.5 s) until the user has answered the Bluetooth question. Main thread.
    private func afterBluetoothAnswer(tries: Int, _ then: @escaping () -> Void) {
        if CBManager.authorization != .notDetermined || tries <= 0 { return then() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.afterBluetoothAnswer(tries: tries - 1, then) }
    }

    /// "Battery saver" (Connections): no Wi-Fi network links and fewer relay requests. Bluetooth keeps running.
    static var saver: Bool { UserDefaults.standard.bool(forKey: "saver") }
    private var wifiWanted: Bool { (UserDefaults.standard.object(forKey: "wifiNetwork") as? Bool ?? true) && !Self.saver }

    func setSaver(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: "saver")
        if wifiWanted { wifi.start() } else { wifi.stop() }
        nostr.setSaver(on)
    }

    var statusLines: [String] { status.keys.sorted().compactMap { status[$0] } }

    /// Turns linking over Wi-Fi networks on or off (Connections screen), and remembers it.
    func setWifi(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: "wifiNetwork")
        if wifiWanted { wifi.start() } else { wifi.stop() }
    }

    /// Turns the internet relays on or off (Connections screen), and remembers it.
    func setInternet(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: "internet")
        if on { nostr.start() } else { nostr.stop() }
    }

    /// Turns "Connect through Tor" on or off (Connections screen), and remembers it.
    func setTor(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: "tor")
        nostr.setTor(on)
        OfflineMap.shared.applyNetwork()
    }

    /// This phone's relay mailboxes (spec/FORMAT.md, "Mailboxes"): its group's, the other saved groups', the Public
    /// channel's last. Any thread.
    private func relayScopes() -> [NostrLink.Scope] {
        let set = keySet
        let groups: [NostrLink.Scope] = ([set.active].compactMap { $0 } + set.others).filter { !$0.isPublic }.map { k in
            var boxes: [UInt16] = []
            for m in k.ring.all.map(\.group.mailbox) + ([k.door] + k.oldDoors).map(\.crypto.mailbox) where !boxes.contains(m) { boxes.append(m) }
            return NostrLink.Scope(id: k.id, mailboxes: boxes)
        }
        return groups + [NostrLink.Scope(id: "", mailboxes: [Nostr.publicMailbox])]
    }

    /// The cached keys of `code`, derived the first time (32 MiB of scrypt). Any thread; never holds a lock while
    /// deriving, so the main thread never waits for another group's key.
    private func keys(_ code: String) -> Keys {
        if let k = keyLock.withLock({ keyCache[code] }) { return k }
        let k = Keys(code: code)
        loadKnown(k)
        loadRing(k)
        return keyLock.withLock { if let other = keyCache[code] { return other }; keyCache[code] = k; return k }
    }

    // MARK: - Member keys (spec/FORMAT.md, "Signatures", "Introductions")

    /// The public keys saved for `k`'s group: member id -> ["s": seen ms, "p": signing key hex, "e": encryption key hex, "a": when it was introduced, "q": ML-KEM key hex, "n": name].
    private func loadKnown(_ k: Keys) {
        let saved = UserDefaults.standard.dictionary(forKey: "known.\(k.id)") as? [String: [String: String]] ?? [:]
        var out: [String: Known] = [:]
        for (id, v) in saved {
            guard let p = v["p"], let c = MemberKey.Checker(Self.unhex(p)) else { continue }
            out[id] = Known(checker: c, enc: v["e"].map(Self.unhex), name: v["n"] ?? "", encAt: Int64(v["a"] ?? "") ?? 0, pq: v["q"].map(Self.unhex))
        }
        k.lock.withLock { k.known = out }
    }

    /// A member's public keys from a checked introduction: saved (the 500 most recently seen per group stay). True if new.
    @discardableResult private func learn(_ k: Keys, _ id: String, _ c: MemberKey.Checker, enc: Data? = nil, encAt: Int64 = 0, pq: Data? = nil, name who: String = "") -> Bool {
        let (fresh, cur): (Bool, Known) = k.lock.withLock {
            let had = k.known[id]
            let newer = enc != nil && EncSchedule.isNewer(known: had?.encAt ?? 0, ts: encAt)
            let now = Known(checker: c, enc: newer ? enc : had?.enc, name: who.isEmpty ? had?.name ?? "" : who, encAt: newer ? encAt : had?.encAt ?? 0, pq: newer ? pq : had?.pq)
            k.known[id] = now
            return (had == nil, now)
        }
        let d = UserDefaults.standard, key = "known.\(k.id)"
        knownLock.lock(); defer { knownLock.unlock() } // read, change, write: two at once would lose a key
        var saved = d.dictionary(forKey: key) as? [String: [String: String]] ?? [:]
        let hex: (Data) -> String = { $0.map { String(format: "%02x", $0) }.joined() }
        var v = saved[id] ?? [:]
        v["s"] = String(Self.nowMs()); v["p"] = hex(c.pub)
        if let e = cur.enc { v["e"] = hex(e); v["a"] = String(cur.encAt); v["q"] = cur.pq.map(hex) }
        if !who.isEmpty { v["n"] = who }
        saved[id] = v
        if saved.count > Self.maxKnown {
            // The least recently seen go, but never someone in the group, or new keys for them couldn't be sealed.
            let members = Set(k.members)
            let old = saved.filter { !members.contains($0.key) && $0.key != id }.sorted { (Int64($0.value["s"] ?? "") ?? 0) < (Int64($1.value["s"] ?? "") ?? 0) }
            for (id, _) in old.prefix(saved.count - Self.maxKnown) { saved.removeValue(forKey: id); k.lock.withLock { _ = k.known.removeValue(forKey: id) } } // in memory too: a flood of made-up members can't fill it
        }
        d.set(saved, forKey: key)
        return fresh
    }

    /// `k`'s epoch secrets from the Keychain. A group this phone founded (created here, or saved before v0.6) and that
    /// has none gets epoch 1 now, with this phone as its only member and admin (spec "Making the first epoch").
    private func loadRing(_ k: Keys) {
        guard !k.isPublic else { return }
        if let raw = Vault.get("epochs.\(k.id)"), let list = try? JSONSerialization.jsonObject(with: raw) as? [[String: Any]] {
            for o in list {
                guard let n = (o["n"] as? NSNumber)?.int64Value, let made = (o["made"] as? NSNumber)?.int64Value, let s = o["s"] as? String else { continue }
                func text(_ n: String) -> String? { (o[n] as? String).flatMap { $0.isEmpty ? nil : $0 } }
                k.ring.add(.init(number: n, made: made, secret: Self.unhex(s), members: o["m"] as? [String] ?? [], admins: o["a"] as? [String] ?? [],
                                 code: text("c"), via: text("v"), removes: text("r"), by: text("b"), rank: (o["k"] as? NSNumber)?.intValue ?? .max))
            }
        }
        if let raw = Vault.get("mkeys.\(k.id)") {
            let b = [UInt8](raw); var i = 0
            while i + 68 <= b.count {
                let hash = String(decoding: b[i..<(i + 64)], as: UTF8.self), n = b[(i + 64)..<(i + 68)].reduce(0) { $0 << 8 | Int($1) }
                i += 68
                guard i + n <= b.count else { break }
                if let e = k.ring.all.first(where: { $0.hash == hash }) { e.messageKeys = MessageKeys.decode(Data(b[i..<(i + n)])) }
                i += n
            }
        }
        var via: [String] = []
        for c in k.ring.all.compactMap(\.via) where c != k.code && !via.contains(c) { via.append(c) }
        k.setDoors(k.door, old: via.map(Door.init))
        let d = UserDefaults.standard
        k.rejoiningSince = Int64(d.double(forKey: "rejoining.\(k.id)"))
        if let p = d.string(forKey: "removedAt.\(k.id)")?.split(separator: ":"), p.count == 2, let n = Int64(p[0]), let r = Int(p[1]) { k.removedAt = (n, r) }
        var found = Set(GroupSecrets.shared.found)
        if !k.joined && found.contains(k.code) {
            var b = [UInt8](repeating: 0, count: 32); _ = SecRandomCopyBytes(kSecRandomDefault, 32, &b)
            k.ring.add(.fresh(number: 1, made: Self.nowMs(), secret: Data(b), members: [k.me], admins: [k.me]))
            saveRing(k)
            found.remove(k.code); GroupSecrets.shared.setFound(Array(found))
            #if DEBUG
            DebugLog.write("epoch 1 made for a group founded here")
            #endif
        }
    }

    private func saveRing(_ k: Keys) {
        saveMessageKeys(k)
        let hex: (Data) -> String = { $0.map { String(format: "%02x", $0) }.joined() }
        let list: [[String: Any]] = k.ring.all.map { ["n": $0.number, "made": $0.made, "s": hex($0.secret), "m": $0.members, "a": $0.admins,
                                                  "c": $0.code ?? "", "v": $0.via ?? "", "r": $0.removes ?? "", "b": $0.by ?? "", "k": $0.rank] }
        Vault.put("epochs.\(k.id)", try? JSONSerialization.data(withJSONObject: list))
    }

    /// Marks `code` as founded on this phone (a new group): its first epoch is made here.
    static func found(_ code: String) {
        let d = UserDefaults.standard
        GroupSecrets.shared.setFound(Array(Set(GroupSecrets.shared.found).union([code])))
    }

    /// True while this phone has the code of `code`'s group but no epoch yet: it is asking to join.
    func joining(_ code: String?) -> Bool {
        guard let code, let k = keyLock.withLock({ keyCache[code] }) else { return false }
        return !k.isPublic && !k.joined
    }

    private func held(_ code: String?) -> Keys? { guard let code else { return nil }; return keyLock.withLock { keyCache[code] } }
    private func memberId(_ k: Keys, _ id: String) -> String { id == deviceId ? k.me : id.hasPrefix("web-") ? String(id.dropFirst(4)) : id }

    /// True if this phone was removed from `code`'s group.
    func removed(_ code: String?) -> Bool { held(code)?.removed ?? false }
    /// True if `code` is an invite this phone is trying to join with and the group has moved on from it.
    func inviteClosed(_ code: String?) -> Bool { held(code).map { $0.closed && (!$0.joined || $0.rejoining) } ?? false }
    /// True while this phone, back after more than a week, waits for someone in `code`'s group to answer.
    func rejoining(_ code: String?) -> Bool { held(code)?.rejoining ?? false }

    /// Makes the weekly new key of every saved group that is due. On `work`.
    func weeklyCheck() { let s = keySet; for k in [s.active].compactMap({ $0 }) + s.others { rekeyIfDue(k); finishRemovals(k) } }

    private func hourly() {
        work.asyncAfter(deadline: .now() + .seconds(Int(Keyring.hourMs / 1000))) { [weak self] in
            guard let self else { return }
            self.weeklyCheck(); self.compact(); self.hourly()
        }
    }

    /// A new key when the current one is a week old (spec "Keys"), after this phone's random delay so that the group's
    /// phones don't all do it at once; the first to do it settles it for the rest. Well past that delay this phone has
    /// missed the group's new keys, or the whole group was quiet: its new key is then also how it asks to come back.
    private func rekeyIfDue(_ k: Keys) {
        guard let cur = k.ring.currentOrNil, !k.isPublic, !k.removed, Keyring.weeklyDue(made: cur.made, now: Self.clock(), delay: k.weeklyDelay) else { return }
        let away = Keyring.overdue(made: cur.made, now: Self.clock())
        if makeRekey(k, add: [], answers: nil) && away { setRejoining(k, Self.nowMs()) }
    }

    /// The time, for deciding when a key is due; tests can move it forward.
    private static func clock() -> Int64 {
        #if DEBUG
        return nowMs() + ahead
        #else
        return nowMs()
        #endif
    }
    #if DEBUG
    /// Moves the clock that decides when a key is due: launch argument `ahead 8` (days).
    static var ahead: Int64 = 0
    #endif

    private func setRejoining(_ k: Keys, _ since: Int64) {
        guard k.rejoiningSince != since else { return }
        k.rejoiningSince = since
        UserDefaults.standard.set(Double(since), forKey: "rejoining.\(k.id)")
        DispatchQueue.main.async { self.refresh() }
    }

    /// The rekey really is from who it says: its key matches the sender's id, and it signed the packet.
    private func signed(_ o: GroupCrypto.Opened, _ r: Rekey) -> Bool {
        guard MemberKey.id(r.maker) == o.message.sender, let c = MemberKey.Checker(r.maker) else { return false }
        return c.verify(digest: o.digest, signature: o.signature)
    }

    /// A member's phone missed our keys: a new epoch, sealed to everyone, brings it back (spec "Away for a while"). Not if
    /// another member answered first, or this phone made a key in the last hour (a flood of these must not cost more than that).
    private func answerBehind(_ k: Keys, made: Int64) {
        guard let cur = k.ring.currentOrNil, !k.removed, cur.made < made, !k.ring.tooSoon(k.me, made: Self.clock()) else { return }
        makeRekey(k, add: [], answers: nil)
    }
    /// The admins an invite to `code`'s group names (spec "Invites"), first listed first, or nil until its keys are loaded.
    func invitePins(_ code: String) -> String? {
        guard let k = held(code) else { return nil }
        let pubs = (k.ring.currentOrNil?.admins ?? []).compactMap { $0 == k.me ? k.pub : k.checker($0)?.pub }
        return pubs.prefix(Invite.maxPins).map(Invite.pin).joined()
    }

    func isAdmin(_ code: String?, _ id: String) -> Bool { held(code).map { $0.ring.currentOrNil?.admins.contains(memberId($0, id)) ?? false } ?? false }
    func inGroup(_ code: String?, _ id: String) -> Bool { held(code).map { $0.members.contains(memberId($0, id)) } ?? false }

    /// Gives `id` the admin role, with a new key. `done` says on the main thread if it worked.
    func makeAdmin(_ code: String?, _ id: String, done: @escaping (Bool) -> Void) {
        adminChange(code, id, done) { k, m, cur in !cur.admins.contains(m) && self.makeRekey(k, add: [], answers: nil, admins: cur.admins + [m]) }
    }

    /// Removes `id`: a new key and a new code for everyone else (spec "Removing and the code").
    func remove(_ code: String?, _ id: String, done: @escaping (Bool) -> Void) {
        adminChange(code, id, done) { k, m, _ in m != k.me && self.makeRekey(k, add: [], answers: nil, remove: m) }
    }

    private func adminChange(_ code: String?, _ id: String, _ done: @escaping (Bool) -> Void, _ act: @escaping (Keys, String, Keyring.Epoch) -> Bool) {
        work.async {
            var ok = false
            if let k = self.held(code), let cur = k.ring.currentOrNil, !k.removed, cur.admins.contains(k.me) {
                let m = self.memberId(k, id)
                ok = cur.members.contains(m) && act(k, m, cur)
            }
            DispatchQueue.main.async { done(ok); self.refresh() }
        }
    }

    /// What happened in `code`'s group, by name and when: "Marco joined", "Anna removed Marco", "Anna made Ben an admin".
    func groupLines(_ code: String?) -> [GroupEvent] {
        guard let k = held(code) else { return [] }
        let eps = k.ring.all.filter { k.ring.won($0) }.sorted { $0.number < $1.number }
        guard eps.count > 1 else { return [] }
        func name(_ id: String?) -> String { let n = id.flatMap { i in k.lock.withLock { k.known[i]?.name } } ?? ""; return n.isEmpty ? "Someone" : n }
        func subject(_ id: String?) -> String { id == k.me ? "You" : name(id) }
        func object(_ id: String?) -> String { id == k.me ? "you" : name(id) }
        var out: [GroupEvent] = []
        for (a, b) in zip(eps, eps.dropFirst()) {
            for id in b.members where !a.members.contains(id) && id != k.me { out.append(GroupEvent(ts: b.made, text: "\(name(id)) joined")) }
            for id in b.admins where !a.admins.contains(id) { out.append(GroupEvent(ts: b.made, text: "\(subject(b.by)) made \(object(id)) an admin")) }
            if let id = b.removes { out.append(GroupEvent(ts: b.made, text: "\(subject(b.by)) removed \(object(id))")) }
        }
        return out
    }

    /// A new epoch from a rekey (spec "New key"): signed by its maker, allowed by `Keyring.admit`, with a part this
    /// phone can open. A removal also moves the group to its new code. True if it was new.
    private func acceptRekey(_ k: Keys, _ o: GroupCrypto.Opened, _ r: Rekey, _ packetId: String, _ door: Door) -> Bool {
        let maker = o.message.sender
        guard signed(o, r) else { return false }
        let pinned = Invite.allows(GroupSecrets.shared.pins(k.code), maker: r.maker) // only read while this phone has no epoch
        #if DEBUG
        if !pinned && !k.joined { DebugLog.write("new key from someone this invite doesn't name: ignored") }
        #endif
        if r.removal && k.rejoining && maker != k.me { k.closed = true } // the group may have moved on while this phone was away
        switch k.ring.take(r, maker: maker, me: k.me, door: door.code, oldDoor: door !== k.door, removedAt: k.removedAt, pinned: pinned, open: { k.encs.open($0, info: Rekey.info(door.id), aad: Rekey.aad(packetId, k.me)) }) {
        case .ignored:
            return false
        case .closed:
            k.closed = true
            DispatchQueue.main.async { self.refresh() }
            return false
        case .removed(let number, let rank):
            k.removedAt = (number, rank)
            UserDefaults.standard.set("\(number):\(rank)", forKey: "removedAt.\(k.id)")
            #if DEBUG
            DebugLog.write("removed from a group by \(o.message.name)")
            #endif
            DispatchQueue.main.async { self.refresh() }
            return false
        case .added(let e, let moveTo, let back):
            if back { k.removedAt = nil; UserDefaults.standard.removeObject(forKey: "removedAt.\(k.id)") }
            if moveTo != nil { moveDoor(k) }
            saveRing(k)
            if k.ring.current === e && maker != k.me { setRejoining(k, 0) }
            DispatchQueue.main.async { if let held = self.waitingToJoin.removeValue(forKey: k.id) { for w in held { self.send(w.text, photo: w.photo, group: k.code) } } }
            #if DEBUG
            DebugLog.write("epoch \(r.epoch) from \(o.message.name): \(r.members.count) member(s)\(r.removal ? ", after a removal" : "")")
            #endif
            return true
        }
    }

    /// Two admins removed different people at once: only one removal won, so the other person is still in the current
    /// epoch. An admin's phone finishes it, after 0-3 s unless another admin did (spec "Two new keys at the same time").
    private func finishRemovals(_ k: Keys) {
        guard !k.removed, k.ring.currentOrNil?.admins.contains(k.me) == true else { return }
        for m in k.ring.stillToRemove() where m != k.me { if !makeRekey(k, add: [], answers: nil, remove: m) { return } }
    }

    /// The group follows the code of its newest removal (`Keyring.lastMove`): same group id, member keys and messages, a
    /// new door and a new invite. Taken from the keyring, so a removal made here and one arriving at the same moment end
    /// up on the same code.
    private func moveDoor(_ k: Keys) {
        k.moveLock.lock(); defer { k.moveLock.unlock() }
        guard let code = k.ring.lastMove?.code else { return }
        let old = k.door
        guard old.code != code else { return }
        let next = Door(code)
        Vault.put("origin.\(next.id)", Data(k.id.utf8))
        k.setDoors(next, old: [old] + k.oldDoors.filter { $0.code != code })
        keyLock.withLock { keyCache.removeValue(forKey: old.code); keyCache[code] = k }
        SavedGroups.replaceCode(old.code, code)
        let d = UserDefaults.standard
        d.removeObject(forKey: "introAt.\(k.id)") // introduce ourselves through the new door
        #if DEBUG
        DebugLog.write("the group moved to a new code")
        #endif
        DispatchQueue.main.async {
            if GroupSecrets.shared.current == old.code { GroupSecrets.shared.setCode(code) } // on the main thread: the screens watch it
            if self.activeCode == old.code { self.activeCode = code }
            Unread.shared.rename(old.code, code)
            for i in self.raw.indices where self.raw[i].group == old.code { self.raw[i].group = code }
            self.refresh()
        }
    }

    private func declined(_ k: Keys) -> Set<String> { Set(UserDefaults.standard.stringArray(forKey: "declined.\(k.id)") ?? []) }

    /// People asking to join `code`'s group, for this phone to answer if it is an admin: they introduced themselves through
    /// the door in the last week and aren't in the group, weren't removed and weren't turned down.
    func joinRequests(_ code: String?) -> [JoinRequest] {
        guard let k = held(code), let cur = k.ring.currentOrNil, !k.removed, cur.admins.contains(k.me) else { return [] }
        let gone = Set(k.ring.all.compactMap(\.removes)), no = declined(k), cut = Self.nowMs() - 7 * 24 * 3_600_000
        return k.lock.withLock {
            k.known.filter { id, w in id != k.me && !cur.members.contains(id) && !gone.contains(id) && !no.contains(id) && w.pq != nil && w.encAt >= cut }
                .map { JoinRequest(id: $0.key, name: $0.value.name.isEmpty ? "Someone" : $0.value.name, pub: $0.value.checker.pub) }
        }.sorted { $0.id < $1.id }
    }

    /// An admin lets `id` in: a new epoch for everyone, them included (spec "Joining"). `done` says on the main thread if it worked.
    func approveJoin(_ code: String?, _ id: String, done: @escaping (Bool) -> Void) {
        work.async {
            var ok = false
            if let k = self.held(code), let cur = k.ring.currentOrNil, !k.removed, cur.admins.contains(k.me), !cur.members.contains(id) {
                ok = self.makeRekey(k, add: [id], answers: id)
            }
            DispatchQueue.main.async { done(ok); self.refresh() }
        }
    }

    /// An admin turns `id` down. They can ask again only with a new key, that is by reinstalling.
    func declineJoin(_ code: String?, _ id: String) {
        guard let k = held(code) else { return }
        UserDefaults.standard.set(Array(declined(k).union([id])), forKey: "declined.\(k.id)")
        DispatchQueue.main.async { self.refresh() }
    }

    /// Makes and sends a new epoch for the current members plus `add`, sealed to each member's encryption key. `admins`:
    /// a new admin list. `remove`: who leaves; everyone else also gets a new code. False if a member's encryption key
    /// hasn't reached this phone yet: leaving them out would quietly remove them.
    @discardableResult private func makeRekey(_ k: Keys, add: [String], answers: String?, admins: [String]? = nil, remove: String? = nil) -> Bool {
        guard let cur = k.ring.currentOrNil else { return false }
        var members = cur.members.filter { $0 != remove }
        for m in [k.me] + add where !members.contains(m) { members.append(m) }
        guard members.count <= Keyring.maxMembers else {
            #if DEBUG
            DebugLog.write("rekey: the group is full")
            #endif
            return false
        }
        let door = k.door, code = remove == nil ? nil : Invite.newCode(), now = Self.nowMs()
        var b = [UInt8](repeating: 0, count: 32); _ = SecRandomCopyBytes(kSecRandomDefault, 32, &b)
        let secret = Data(b), plain = Rekey.box(secret, code: code)
        // An admin's rekey also keeps every admin added by a rekey of the same number that didn't win.
        var list: [String] = []
        for a in (admins ?? cur.admins) + (cur.admins.contains(k.me) ? k.ring.rivalAdmins() : []) where members.contains(a) && !list.contains(a) { list.append(a) }
        let who = DispatchQueue.main.sync { name }
        // A big group's key goes in several packets, each with the whole member list and some members' parts.
        var packets: [Packet] = [], made: Rekey?
        for some in Rekey.split(members) {
            let pid = Packet.newId(mailbox: door.rekeys.mailbox)
            var parts: [(id: String, box: Data)] = []
            for m in some {
                let known = m == k.me ? nil : k.lock.withLock { k.known[m] }
                let enc = m == k.me ? k.encPub : known?.enc, pq = m == k.me ? k.encs.currentPq : known?.pq
                guard let enc, let pq, let pk = try? P256.KeyAgreement.PublicKey(x963Representation: enc),
                      let box = try? Hybrid.seal(plain, to: pk, pq: pq, info: Rekey.info(door.id), aad: Rekey.aad(pid, m)) else {
                    #if DEBUG
                    DebugLog.write("rekey: no encryption key for \(m) yet")
                    #endif
                    return false
                }
                parts.append((m, box))
            }
            let one = Rekey(epoch: cur.number + 1, made: now, maker: k.pub, admins: list, answers: remove ?? answers, parts: parts, removal: remove != nil, members: members)
            guard let c = try? door.rekeys.seal(id: pid, ts: now, sender: k.me, name: who, text: "", extra: one.encode(), pad: .full, sign: { try k.sign($0) }) else { return false } // always the largest size: its length would count the members
            packets.append(Packet(id: pid, ts: door.rekeys.hideTime(now, c), ttl: Self.maxTtl, cipher: c))
            made = one
        }
        guard let rk = made else { return false }
        k.ring.add(.fresh(number: rk.epoch, made: now, secret: secret, members: members, admins: list, code: code, via: remove == nil ? nil : door.code, removes: remove, by: k.me,
                         rank: remove == nil ? .max : k.ring.rank(rk, maker: k.me)))
        if code != nil { moveDoor(k) }
        saveRing(k)
        for p in packets {
            idsLock.withLock { _ = myReceipts.insert(p.id) }
            store.append(p)
            indexed(p, .group)
            router.publish(p)
        }
        if code != nil { introIfDue(k) }
        nostr.resubscribe()
        #if DEBUG
        DebugLog.write("epoch \(rk.epoch) made: \(members.count) member(s) in \(packets.count) packet(s)" + (answers.map { ", answering \($0)" } ?? "") + (remove.map { ", removing \($0)" } ?? ""))
        #endif
        DispatchQueue.main.async { self.refresh() }
        return true
    }

    /// true: signed by that member; false: not (forged or broken); nil: the member's public key isn't known yet.
    private func check(_ k: Keys, _ o: GroupCrypto.Opened) -> Bool? {
        let id = o.message.sender.hasPrefix("web-") ? String(o.message.sender.dropFirst(4)) : o.message.sender
        if k.ring.removed(id, before: o.message.ts) { return false } // written after they were removed
        guard let c = k.checker(id) else { return nil }
        return c.verify(digest: o.digest, signature: o.signature)
    }

    /// Messages and receipts of `id` in `k`'s group that waited for its key: shown as checked, or dropped. Main thread.
    private func resolve(_ k: Keys, _ id: String) {
        let waiting = pending.values.filter { $0.k === k && $0.sender == id }
        guard !waiting.isEmpty else { return }
        for w in waiting {
            pending.removeValue(forKey: w.o.message.id)
            let ok = check(k, w.o) == true
            if let r = w.receipt { if ok { receiptMsgs[r.id] = r; deliveries.add(r) }; continue }
            guard let i = raw.firstIndex(where: { $0.id == w.o.message.id }) else { continue }
            if ok { raw[i].verified = true; w.o.leaf?.forget(); saveMessageKeys(w.k) } else { rawIds.remove(raw[i].id); raw.remove(at: i) }
        }
        refresh()
    }

    /// Sends this phone's introduction to `k`'s group when the last one there is more than 3 days old (or there was
    /// none), so members' introductions are always among the packets of the last 7 days. Any thread.
    private func introIfDue(_ k: Keys) {
        guard !k.removed else { return }
        let d = UserDefaults.standard, key = "introAt.\(k.id)", now = Self.nowMs()
        let rotated = !k.isPublic && k.encs.rotateIfDue(now: Self.clock()) // a new encryption key has to be introduced at once
        guard rotated || now - Int64(d.double(forKey: key)) >= Self.introEvery else { return }
        let id = Packet.newId(mailbox: k.intros.mailbox), who = DispatchQueue.main.sync { name }
        let pq = k.isPublic ? nil : k.encs.currentPq // the Public channel has no new keys to seal
        guard let c = try? k.intros.seal(id: id, ts: now, sender: k.me, name: who, text: "", extra: pq.map { Data([3]) + k.pub + k.encPub + $0 } ?? Data([2]) + k.pub + k.encPub, sign: { try k.sign($0) })
        else { return }
        let p = Packet(id: id, ts: k.intros.hideTime(now, c), ttl: Self.maxTtl, cipher: c)
        idsLock.withLock { _ = myReceipts.insert(id) } // written here: goes up to the relays first, like receipts
        store.append(p)
        indexed(p, k.isPublic ? .isPublic : .group)
        d.set(Double(now), forKey: key)
        router.publish(p)
        #if DEBUG
        DebugLog.write("introduction sent to \(k.isPublic ? "Everyone" : "a group")")
        #endif
    }

    // People whose emoji the user compared (spec "Person emoji"): "<group tag>|<member id>|<name key>".
    private func tagOf(_ code: String?) -> String? { keyLock.withLock { keyCache[code ?? GroupCrypto.publicCode] }?.id }
    private var checkedList: [String] { UserDefaults.standard.stringArray(forKey: "checked") ?? [] }

    func isChecked(_ code: String?, _ id: String) -> Bool {
        guard let t = tagOf(code) else { return false }
        return checkedList.contains { $0.hasPrefix("\(t)|\(id)|") }
    }

    /// The user compared `id`'s emoji and they matched: this key is that person's from now on (an older one for the name goes).
    func markChecked(_ code: String?, _ id: String, _ name: String) {
        guard let t = tagOf(code) else { return }
        let key = Vouch.key(name)
        var list = checkedList.filter { !($0.hasPrefix("\(t)|") && ($0.hasSuffix("|\(key)") || $0.hasPrefix("\(t)|\(id)|"))) }
        list.append("\(t)|\(id)|\(key)")
        UserDefaults.standard.set(list, forKey: "checked")
        objectWillChange.send()
    }

    /// True if `name` belongs to a checked person but `id` is another key: a reinstall, or someone using their name.
    func newKeyFor(_ code: String?, _ id: String, _ name: String) -> Bool {
        guard id != deviceId, let t = tagOf(code) else { return false }
        let key = Vouch.key(name)
        return checkedList.contains { $0.hasPrefix("\(t)|") && $0.hasSuffix("|\(key)") && !$0.hasPrefix("\(t)|\(id)|") }
    }

    /// This phone's public key in `code`'s group ("your emoji"), or nil if its keys aren't ready.
    func myPublicKey(_ code: String?) -> Data? { keyLock.withLock { keyCache[code ?? GroupCrypto.publicCode] }?.pub }

    /// The public key of member `id` in `code`'s group, if an introduction brought it.
    func publicKey(of id: String, in code: String?) -> Data? {
        guard let k = keyLock.withLock({ keyCache[code ?? GroupCrypto.publicCode] }) else { return nil }
        return k.checker(id.hasPrefix("web-") ? String(id.dropFirst(4)) : id)?.pub
    }

    /// Switches to another group (or just another name) without restarting the radios: every phone relays every
    /// group anyway, and saved groups' messages are already read. Only the name changed: nothing else happens. A new
    /// group's key is derived in the background. Call on the main thread.
    func rejoin(name: String, code: String) {
        self.name = name
        guard code != activeCode else { return }
        flushAcks() // confirmations owed so far go out first
        activeCode = code
        refresh() // a saved group's messages show at once
        work.async { self.savedGroupsChanged(code) }
    }

    /// After blocking, unblocking or reporting: shows the messages again with the new rules. Main thread; no reading.
    func moderationChanged() { refresh() }

    // MARK: - Loading (background, on `work`)

    /// Passes stored packets on right away (no keys needed), then reads them with this group's and the Public key, then
    /// with the other saved groups' keys, then trims the store.
    private func startUp(_ code: String) {
        let now = Self.nowMs(), cut = now - Self.week
        var recent: [Packet] = [], seen = Set<String>()
        store.forEach { p in
            guard p.ts >= cut, !MeshRouter.inFuture(p.ts, now: now) else { return }
            seen.insert(MeshRouter.key(p)); recent.append(p)
            if recent.count >= 2_000 { recent.sort { $0.ts > $1.ts }; recent.removeLast(recent.count - 500) }
        }
        router.restore(recent, seenIds: seen) // the router keeps the newest 500
        let a = keys(code), pub = keys(GroupCrypto.publicCode)
        cryptoLock.withLock { _active = a; _public = pub }
        load()
        nostr.resubscribe()
        savedGroupsChanged(code)
        hourly()
    }

    /// `code` is the group on screen and the saved list may have changed: derives the keys not seen before, reads the
    /// store again only if there are any, then trims the store.
    private func savedGroupsChanged(_ code: String) {
        let known = keyLock.withLock { Set(keyCache.keys) }
        var codes: [String] = []
        for c in SavedGroups.all().map(\.code) where c != code && !codes.contains(c) { codes.append(c) }
        let a = keys(code), o = codes.map(keys)
        cryptoLock.withLock { _active = a; _others = o }
        if !(codes + [code]).allSatisfy(known.contains) { load() }
        storeLock.withLock { allKeys = true }
        for k in [a] + o + [keySet.pub].compactMap({ $0 }) { introIfDue(k) }
        for k in [a] + o { rekeyIfDue(k) }
        compact()
        nostr.resubscribe() // the relays now send every saved group's mailbox
    }

    /// Reads every stored packet with every key known so far: messages, receipts, my own ids and the store index.
    /// Packets dated more than 10 minutes ahead are removed. Publishes on the main thread.
    private func load() {
        let k = keySet, now = Self.nowMs()
        var msgs: [Message] = [], recs: [Message] = [], own = Set<String>(), ownR = Set<String>(), rIds = Set<String>()
        var idx: [String: StoreCap.Entry] = [:], future = Set<String>()
        var opened: [(Message, Keys, GroupCrypto.Opened, Bool, Bool)] = [] // checked once every introduction is known
        var copies: [String: Data] = [:]
        history.forEach { copies[$0.id] = $0.cipher }
        store.forEach { stored in
            let p = MeshRouter.clamp(stored)
            if let had = idx[p.id], had.kind != .unreadable { return } // a record written twice; a readable packet does replace junk sent first under its id
            if MeshRouter.inFuture(p.ts, now: now) { future.insert(p.id); return }
            // Introductions are learned at once; messages and receipts are checked after the loop, when every
            // introduction in the store is known, whatever their order.
            let kind: StoreCap.Kind
            switch copies[p.id].flatMap({ fromHistory(p.id, $0, k) }) ?? see(p, k) {
            case .intro(let keys, let id, let c, let enc, let who, let ts, let pq)?: learn(keys, id, c, enc: enc, encAt: ts, pq: pq, name: who); kind = keys.isPublic ? .isPublic : .group
            case .newKey(let keys, let o, let r, let pid, let d)?: _ = acceptRekey(keys, o, r, pid, d); kind = .group
            case .msg(let m, let keys, let o, let copy)?: opened.append((m, keys, o, false, copy)); kind = m.isPublic ? .isPublic : .group
            case .receipt(let r, let keys, let o)?: opened.append((r, keys, o, true, false)); rIds.insert(p.id); kind = .group
            default: kind = .unreadable
            }
            idx[p.id] = StoreCap.Entry(id: p.id, ts: p.ts, size: Packet.headerSize + p.cipher.count, kind: kind)
        }
        var waiting: [Pending] = [], spent: [Keys] = []
        for (m, keys, o, receipt, copy) in opened {
            switch check(keys, o) {
            case true?:
                if receipt { recs.append(m); if m.sender == deviceId { ownR.insert(m.id) } }
                else {
                    msgs.append(m); if m.sender == deviceId { own.insert(m.id) }
                    if !copy { remember(m.id, keys, o) }
                    if let l = o.leaf { l.forget(); if !spent.contains(where: { $0 === keys }) { spent.append(keys) } }
                }
            case nil:
                if receipt { waiting.append(Pending(k: keys, sender: o.message.sender, o: o, receipt: m)) }
                else { var u = m; u.verified = false; msgs.append(u); waiting.append(Pending(k: keys, sender: o.message.sender, o: o, receipt: nil)); if !copy { remember(m.id, keys, o) } }
            case false?:
                if let e = idx[m.id] { idx[m.id] = StoreCap.Entry(id: e.id, ts: e.ts, size: e.size, kind: .unreadable) }
            }
        }
        spent.forEach(saveMessageKeys)
        if !future.isEmpty {
            store.remove(future)
            history.remove(future)
            #if DEBUG
            DebugLog.write("store: removed \(future.count) packets dated in the future")
            #endif
        }
        idsLock.withLock { mine.formUnion(own); myReceipts.formUnion(ownR); rIds.forEach { receiptIds.add($0) } }
        storeLock.withLock {
            for (id, e) in index where idx[id] == nil { idx[id] = e } // stored while reading
            index = idx; indexBytes = idx.values.reduce(0) { $0 + $1.size }
        }
        DispatchQueue.main.async {
            for m in msgs where self.rawIds.insert(m.id).inserted { self.raw.append(m) }
            self.raw.sort { $0.ts < $1.ts }
            for r in recs { self.receiptMsgs[r.id] = r }
            self.deliveries = Deliveries(Array(self.receiptMsgs.values))
            for w in waiting where self.pending.count < Self.maxPending { self.pending[w.o.message.id] = w }
            self.refresh()
        }
    }

    /// Keeps the store small, once every saved group's key has been tried: packets older than 7 days that no saved
    /// group can read go (phones stop passing them on after 7 days anyway), Public messages beyond the newest 2,000
    /// go, and then the store cap (StoreCap: about 40 MB and 20,000 packets, unreadable packets first). Same rules as
    /// the Android app (MeshEngine.compact).
    private func compact() {
        let now = Self.nowMs()
        for k in keyLock.withLock({ Array(keyCache.values) }) where !k.ring.expire(now: now).isEmpty { // keys replaced more than 7 days ago go (v0.6), from the Keychain too
            saveRing(k)
            k.setDoors(k.door, old: k.oldDoors.filter { d in k.ring.all.contains { $0.via == d.code } })
        }
        let drop: Set<String> = storeLock.withLock {
            compacting = false
            guard allKeys else { return [] }
            let cut = Self.nowMs() - Self.week
            var drop = Set(index.values.filter { $0.kind == .unreadable && $0.ts < cut }.map(\.id))
            let pub = index.values.filter { $0.kind == .isPublic }.sorted { ($0.ts, $0.id) < ($1.ts, $1.id) }
            if pub.count > Self.maxPublic { pub.prefix(pub.count - Self.maxPublic).forEach { drop.insert($0.id) } }
            drop.formUnion(StoreCap.overflow(index.values.filter { !drop.contains($0.id) }))
            for id in drop { if let e = index.removeValue(forKey: id) { indexBytes -= e.size } }
            return drop
        }
        guard !drop.isEmpty else { return }
        store.remove(drop)
        history.remove(drop)
        #if DEBUG
        DebugLog.write("store: removed \(drop.count) packets")
        #endif
        DispatchQueue.main.async {
            self.raw.removeAll { drop.contains($0.id) }; self.rawIds.subtract(drop)
            self.refresh()
        }
    }

    /// The store grew well past its cap while running: trim it in the background. Any thread.
    private func compactIfFull() {
        let full = storeLock.withLock {
            guard allKeys, !compacting, indexBytes > StoreCap.maxBytes / 10 * 11 || index.count > StoreCap.maxCount + 1_000 else { return false }
            compacting = true; return true
        }
        if full { work.async { self.compact() } }
    }

    /// Counts `p` in the store. False if the store already has a packet under its id that this one doesn't replace.
    @discardableResult private func indexed(_ p: Packet, _ kind: StoreCap.Kind) -> Bool {
        storeLock.withLock {
            let had = index[p.id]
            guard had == nil || (had?.kind == .unreadable && kind != .unreadable) else { return false } // a readable packet replaces junk sent first under its id
            index[p.id] = StoreCap.Entry(id: p.id, ts: p.ts, size: Packet.headerSize + p.cipher.count, kind: kind)
            indexBytes += Packet.headerSize + p.cipher.count - (had?.size ?? 0)
            return true
        }
    }

    /// A packet that arrived: on disk only if it counts. Packets with one id and different content all reach here, and
    /// what isn't counted could otherwise fill the file without the store cap ever seeing it.
    private func keep(_ p: Packet, _ kind: StoreCap.Kind) { if indexed(p, kind) { store.append(p) } }

    // MARK: - Messages

    /// Shows the messages again: this group's and the Public channel's in `messages`, all groups' in `allMessages`,
    /// without blocked people and reported messages. Main thread.
    private func refresh() {
        let blocked = Moderation.blocked, hidden = Moderation.hidden // read once, not per message
        let visible = raw.filter { blocked[$0.sender] == nil && !hidden.contains($0.id) }
        allMessages = visible
        messages = visible.filter { $0.isPublic || $0.group == activeCode }
    }

    /// Adds a message in time order. Main thread.
    private func add(_ m: Message) {
        guard rawIds.insert(m.id).inserted else { return }
        let i = raw.lastIndex { $0.ts <= m.ts }.map { $0 + 1 } ?? 0
        raw.insert(m, at: i)
        refresh()
    }

    /// The saved name of the group whose code is `code` (`Message.group`), for alerts. Main thread.
    func groupName(_ code: String?) -> String {
        if code == activeCode { return UserDefaults.standard.string(forKey: "groupName") ?? "your group" }
        return SavedGroups.all().first { $0.code == code }?.name ?? "a saved group"
    }

    /// Writes a message from this phone, to the group on screen (or the saved group `group`, e.g. answering its
    /// "Are you safe?") or to the Public channel. Call on the main thread.
    /// Returns false if it is too long for a LoRa radio that is linked now (it still travels the other ways).
    @discardableResult func send(_ text: String, isPublic: Bool = false, photo: Data? = nil, group: String? = nil) -> Bool {
        let target = group.flatMap { $0.isEmpty ? nil : $0 } ?? activeCode
        let code = isPublic ? GroupCrypto.publicCode : target
        let k = keys(code), cr = k.group // cached; derived here only if the user writes within a second of switching
        if !isPublic && k.removed { return true } // the screen no longer offers this
        if !isPublic && !k.joined { waitingToJoin[k.id, default: []].append((text, photo)); return true } // sent once an admin lets this phone in
        work.async { self.introIfDue(k) } // members can check this message only with this phone's key
        let id = Packet.newId(mailbox: cr.mailbox), ts = Int64(Date().timeIntervalSince1970 * 1000)
        guard let c = sealOne(k, cr, isPublic: isPublic, id: id, ts: ts, text: text, photo: photo) else { return true }
        let p = Packet(id: id, ts: cr.hideTime(ts, c), ttl: Self.maxTtl, cipher: c)
        idsLock.withLock { _ = mine.insert(id) }
        store.append(p)
        indexed(p, isPublic ? .isPublic : .group)
        add(Message(id: id, ts: ts, sender: deviceId, name: name, text: text, isPublic: isPublic, photo: isPublic ? nil : photo,
                    group: isPublic ? nil : target))
        router.publish(p)
        return (!lora.connected || Meshtastic.fits(p)) && (!meshcore.connected || MeshCore.fits(p))
    }

    /// Sends a check-in with this phone's battery level and, if you share it, your position (a fresh GPS fix can take
    /// up to 10 s: `checkInSending` is set meanwhile and a second tap is ignored). The haptic comes right away.
    /// `group`: a saved group other than the one on screen. Main thread.
    func checkIn(_ c: CheckIn, needs: Set<Need> = [], people: Int? = nil, group: String? = nil, done: (() -> Void)? = nil) {
        guard checkInSending == nil else { return }
        checkInSending = c
        UINotificationFeedbackGenerator().notificationOccurred(c == .safe ? .success : .warning)
        let battery = Self.batteryPercent
        LocationService.shared.forCheckIn { [weak self] spot in
            guard let self else { return }
            self.send(c.text(battery: battery, spot: spot, needs: needs, people: people), group: group)
            self.checkInSending = nil
            done?()
        }
    }

    private func setStatus(_ key: String, _ line: String?) {
        DispatchQueue.main.async {
            self.status[key] = line
            let bt = self.ble.nodes, mc = self.mc.nodes, net = self.wifi.nodes
            let all = Set(bt).union(mc).union(net) // a phone linked several ways counts once
            self.bluetoothLinks = bt.count; self.wifiLinks = mc.count + net.count; self.wifiNetworkLinks = net.count
            self.linkedNodes = all
            self.phones = all.count; self.radioLinked = self.lora.connected; self.meshcoreLinked = self.meshcore.connected
            self.relaysLinked = self.nostr?.connected ?? 0
            #if DEBUG
            if CommandLine.arguments.contains("fakeRelays") { self.relaysLinked = 4 } // screenshots of the online state, offline
            #endif
            self.throughTor = self.nostr?.throughTor
            self.bluetooth = self.ble.state
            self.localNetworkDenied = self.wifi.localNetworkDenied
            self.watchTor()
        }
    }

    /// With "Connect through Tor": after 2 minutes without getting through, say so (ConnectionsView). Main thread.
    private func watchTor() {
        guard throughTor == false else { torWaitingSince = nil; torSlow = false; return }
        guard torWaitingSince == nil else { return }
        let since = Date()
        torWaitingSince = since
        DispatchQueue.main.asyncAfter(deadline: .now() + 120) { [weak self] in
            guard let self, self.torWaitingSince == since, self.throughTor == false else { return }
            self.torSlow = true
        }
    }

    /// Called by the router while it holds its lock: every transport only queues the packet.
    private func route(_ peer: String, _ p: Packet) {
        let (newlyMine, ownPacket, receipt) = idsLock.withLock {
            (mine.contains(p.id) && !sentIds.contains(p.id), mine.contains(p.id) || myReceipts.contains(p.id), receiptIds.contains(p.id))
        }
        if peer == LoraLink.peer {
            if receipt { return }             // receipts stay off LoRa, where airtime is scarce
            lora.offer(p)
            if !Meshtastic.fits(p) { return } // too long for the radio: not really sent
        }
        else if peer == MeshCoreLink.peer {
            if receipt { return }             // same rules as Meshtastic
            meshcore.offer(p)
            if !MeshCore.fits(p) { return }
        }
        else if peer.hasPrefix(BleLink.prefix) { ble.send(peer, p) }
        else if peer.hasPrefix(MultipeerLink.prefix) { mc.send(peer, p) }
        else if peer.hasPrefix(WifiLink.prefix) { wifi.send(peer, p) }
        // Written on this phone (a message or a receipt): goes up first. "Sent" once a relay accepts it.
        else if peer == NostrLink.peer { nostr.send(p, mine: ownPacket); return }
        if newlyMine { markHandedOff(p.id) }
    }

    /// One of my messages left this phone: to a phone, a radio or the internet relays ("Sent"). Saved on the phone,
    /// so the label survives restarts. Any thread.
    private func markHandedOff(_ id: String) {
        let list: [String]? = idsLock.withLock { mine.contains(id) && sentIds.add(id) ? sentIds.list : nil }
        guard let list else { return }
        UserDefaults.standard.set(list, forKey: "handedOff")
        DispatchQueue.main.async { self.handedOff = Set(list) }
    }

    /// What `p` is: tried with this group's keys, then the Public channel's (photos are group-only; in someone else's
    /// Everyone messages and places, offensive words are masked), then the other saved groups'. `group` says which
    /// group. Nothing is checked yet, except introductions, which carry their own key.
    private func see(_ p: Packet, _ k: (active: Keys?, others: [Keys], pub: Keys?)) -> Seen? {
        let box = Packet.mailbox(of: p.id) // every key has one mailbox: junk costs one try, not one per key this phone holds
        for keys in [k.active, k.pub].compactMap({ $0 }) + k.others {
          for e in keys.ring.all where e.group.mailbox == box {
            if let o = e.open(p) { return message(keys, o) }
            if let o = e.receipts.openSigned(p) { return .receipt(asMine(o.message, keys.me), keys, o) }
          }
          // Only the Public channel reads through its door: in a group the code alone doesn't let anyone write.
          if keys.isPublic, keys.door.crypto.mailbox == box, let o = keys.door.crypto.openSigned(p) { return message(keys, o) }
          if keys.intros.mailbox == box, let o = keys.intros.openSigned(p) { return introduction(keys, o) ?? .forged }
          if !keys.isPublic {
              for d in [keys.door] + keys.oldDoors where d.rekeys.mailbox == box { // old doors: for removals that crossed
                  guard let o = d.rekeys.openSigned(p) else { continue }
                  guard let r = o.extra.flatMap(Rekey.decode) else { return .forged }
                  return .newKey(keys, o, r, p.id, d)
              }
          }
        }
        return nil
    }

    private func message(_ keys: Keys, _ o: GroupCrypto.Opened) -> Seen {
        var m = asMine(o.message, keys.me)
        if keys.isPublic {
            let mine = m.sender == deviceId
            m = Message(id: m.id, ts: m.ts, sender: m.sender, name: mine ? m.name : WordFilter.clean(m.name),
                        text: mine ? m.text : WordFilter.clean(m.text), isPublic: true)
        } else { m.group = keys.code }
        return .msg(m, keys, o, false)
    }

    private static let historyKey: Data = {
        if let k = Vault.get("history"), k.count == 32 { return k }
        var b = [UInt8](repeating: 0, count: 32); _ = SecRandomCopyBytes(kSecRandomDefault, 32, &b)
        Vault.put("history", Data(b))
        return Data(b)
    }()

    /// Keeps a readable copy of a message opened with its own key: that key is about to be deleted.
    private func remember(_ id: String, _ k: Keys, _ o: GroupCrypto.Opened) {
        guard let l = o.leaf, let blob = History.seal(key: Self.historyKey, id: id, group: k.id, epoch: l.epoch.hash, o, index: l.index, counter: l.counter) else { return }
        history.append(Packet(id: id, ts: o.message.ts, ttl: 0, cipher: blob))
    }

    /// A message from this phone's copy, while its epoch is still held: when the epoch goes, the message goes too.
    private func fromHistory(_ id: String, _ blob: Data, _ set: (active: Keys?, others: [Keys], pub: Keys?)) -> Seen? {
        guard let s = History.open(key: Self.historyKey, id: id, blob: blob),
              let k = ([set.active].compactMap({ $0 }) + set.others).first(where: { $0.id == s.group }),
              let e = k.ring.all.first(where: { $0.hash == s.epoch }) else { return nil }
        var o = s.opened
        o.leaf = Leaf(epoch: e, index: s.index, counter: s.counter)
        var m = asMine(o.message, k.me)
        m.group = k.code
        return .msg(m, k, o, true)
    }

    /// Each held epoch's message keys, in the Keychain: they are saved after every message whose key was deleted.
    private func saveMessageKeys(_ k: Keys) {
        k.moveLock.withLock {
            var d = Data()
            for e in k.ring.all {
                guard let m = e.messageKeys?.encode() else { continue }
                d.append(Data(e.hash.utf8))
                d.append(contentsOf: [UInt8(m.count >> 24 & 255), UInt8(m.count >> 16 & 255), UInt8(m.count >> 8 & 255), UInt8(m.count & 255)])
                d.append(m)
            }
            Vault.put("mkeys.\(k.id)", d)
        }
    }

    /// A group message goes under its own key, deleted here at once: from then on only this phone's copy can show it (spec "Message keys").
    private func sealOne(_ k: Keys, _ cr: GroupCrypto, isPublic: Bool, id: String, ts: Int64, text: String, photo: Data?) -> Data? {
        if !isPublic, let e = k.ring.currentOrNil, let keys = e.messageKeys, let i = keys.index(k.me), let n = keys.takeNext(), let mk = keys.key(i, n) {
            guard let c = try? cr.seal(messageKey: mk, index: i, counter: n, id: id, ts: ts, sender: k.me, name: name, text: text, photo: photo, sign: { try k.sign($0) }) else { return nil }
            if var o = cr.open(messageKey: mk, index: i, counter: n, Packet(id: id, ts: ts, ttl: 0, cipher: c), at: ts) {
                o.leaf = Leaf(epoch: e, index: i, counter: n)
                remember(id, k, o)
            }
            keys.forget(i, n)
            saveMessageKeys(k)
            return c
        }
        return try? cr.seal(id: id, ts: ts, sender: k.me, name: name, text: text, photo: isPublic ? nil : photo, sign: { try k.sign($0) })
    }

    /// A valid introduction: the 4th field is 0x02 and a public key whose hash starts with the sender's id, and it signed it.
    private func introduction(_ k: Keys, _ o: GroupCrypto.Opened) -> Seen? {
        guard let e = o.extra else { return nil }
        let withPq = e.count == 99 + MlKem.publicSize && e.first == 3 // 0x03, signing key (33), encryption key (65), ML-KEM key (1184)
        guard withPq || (k.isPublic && e.count == 99 && e.first == 2) else { return nil } // 0x02, without the ML-KEM key: the Public channel only
        if withPq, MlKem.encapsulate(Data(e.suffix(MlKem.publicSize))) == nil { return nil } // a key nobody could seal to would block every new key
        let pub = Data(e[e.startIndex + 1 ..< e.startIndex + 34]), enc = Data(e[e.startIndex + 34 ..< e.startIndex + 99]), id = o.message.sender
        guard o.message.name.utf8.count <= 200, MemberKey.id(pub) == id, (try? P256.KeyAgreement.PublicKey(x963Representation: enc)) != nil, // names are 40 characters at most in the app
              let c = MemberKey.Checker(pub), c.verify(digest: o.digest, signature: o.signature) else { return nil }
        return .intro(k, id, c, enc, o.message.name, o.message.ts, withPq ? Data(e.suffix(MlKem.publicSize)) : nil)
    }

    /// On this phone, its own messages carry `deviceId` as sender: one id for "me" in every group.
    private func asMine(_ m: Message, _ me: String) -> Message { m.sender == me ? m.withSender(deviceId) : m }

    /// A packet seen for the first time: keep it, and show it if a saved group or the Public channel can read it and
    /// its signature checks (or its sender's key isn't known yet: shown as not verified, checked when it comes).
    /// Messages of every saved group are confirmed with that group's receipt key and alerted.
    private func onDeliver(_ p: Packet) {
        #if DEBUG
        DebugLog.write("received \(p.id) sent-at \(p.ts)")
        #endif
        switch see(p, keySet) {
        case .intro(let k, let id, let c, let enc, let who, let ts, let pq)?:
            keep(p, k.isPublic ? .isPublic : .group)
            let fresh = learn(k, id, c, enc: enc, encAt: ts, pq: pq, name: who)
            #if DEBUG
            if fresh { DebugLog.write("introduction \(p.id): key of \(id) (\(who))") }
            #endif
            // Not in the current epoch: a request to join. It waits for an admin here to let them in.
            let asking = fresh && !k.isPublic && !k.removed && id != k.me && !k.members.contains(id) && k.ring.currentOrNil?.admins.contains(k.me) == true && !declined(k).contains(id)
            DispatchQueue.main.async {
                self.resolve(k, id)
                self.refresh()
                if asking { Notifier.shared.received(Message(id: "join-\(id)", ts: Self.nowMs(), sender: id, name: who, text: "asks to join", group: k.code)) }
            }
        case .newKey(let k, let o, let r, let pid, let d)?:
            keep(p, .group)
            if acceptRekey(k, o, r, pid, d) {
                // Our introduction again, at once: newcomers need our keys to check our messages. Messages stored
                // before the epoch came may open now; relays follow its mailbox.
                UserDefaults.standard.removeObject(forKey: "introAt.\(k.id)")
                let first = rescanLock.withLock { () -> Bool in defer { rescanFlag.on = true }; return !rescanFlag.on }
                if first { work.async {
                    self.rescanLock.withLock { self.rescanFlag.on = false }
                    self.load()
                    self.nostr.resubscribe()
                    for g in [self.keySet.active].compactMap({ $0 }) + self.keySet.others { self.introIfDue(g) }
                } }
            }
            // Made after our current epoch, yet numbered below it: that phone missed our keys. Answered after 0-3 s unless another member did.
            if d === k.door, signed(o, r), k.ring.behind(r, maker: o.message.sender) {
                work.asyncAfter(deadline: .now() + .milliseconds(Int.random(in: 0..<3_000))) { self.answerBehind(k, made: r.made) }
            }
            if !k.ring.stillToRemove().isEmpty { work.asyncAfter(deadline: .now() + .milliseconds(Int.random(in: 0..<3_000))) { self.finishRemovals(k) } }
        case .msg(let m0, let k, let o, _)?:
            let ok = check(k, o)
            if ok == false {
                keep(p, .unreadable)
                #if DEBUG
                DebugLog.write("dropped \(p.id): signature doesn't check")
                #endif
                break
            }
            var m = m0; m.verified = ok == true
            keep(p, m.isPublic ? .isPublic : .group)
            remember(p.id, k, o)
            if ok == true, let l = o.leaf { l.forget(); saveMessageKeys(k) } // this message's key is gone: only this phone's copy can show it now
            if k.rejoining, m.sender != deviceId, m.ts >= k.rejoiningSince { setRejoining(k, 0) } // someone wrote in a key this phone has: it's back
            DispatchQueue.main.async {
                if ok == nil, self.pending.count < Self.maxPending { self.pending[m.id] = Pending(k: k, sender: o.message.sender, o: o, receipt: nil) }
                let others = !m.isPublic && m.sender != self.deviceId
                if others { self.ack(m.id, k) }
                self.add(m)
                guard others, Moderation.visible(m) else { return }
                Notifier.shared.received(m)
            }
        case .receipt(let r, let k, let o)?:
            keep(p, .group)
            idsLock.withLock { _ = receiptIds.add(p.id) }
            switch check(k, o) {
            case true?: DispatchQueue.main.async { self.receiptMsgs[r.id] = r; self.deliveries.add(r) }
            case nil: DispatchQueue.main.async { if self.pending.count < Self.maxPending { self.pending[p.id] = Pending(k: k, sender: o.message.sender, o: o, receipt: r) } }
            case false?: break
            }
        default:
            keep(p, .unreadable)
        }
        compactIfFull()
    }

    /// Confirms a group message in the next receipt, with that group's key. Messages arriving less than 2 s apart
    /// share one receipt, for at most 10 s (ReceiptBatch). Main thread.
    private func ack(_ id: String, _ key: Keys) {
        let now = Self.uptimeMs()
        if pendingAcks.isEmpty { firstAck = now; ackTimer(after: ReceiptBatch.quietMs) }
        lastAck = now
        pendingAcks.append((id, key))
    }

    private func ackTimer(after ms: Int64) {
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(Int(ms))) { [weak self] in
            guard let self, !self.pendingAcks.isEmpty else { return }
            let now = Self.uptimeMs()
            if ReceiptBatch.due(firstMs: self.firstAck, lastMs: self.lastAck, nowMs: now) { // a receipt doesn't show how soon this phone got the message
                DispatchQueue.main.asyncAfter(deadline: .now() + Double.random(in: 0..<20)) { [weak self] in self?.flushAcks() }
            }
            else { self.ackTimer(after: Swift.max(10, Swift.min(self.lastAck + ReceiptBatch.quietMs, self.firstAck + ReceiptBatch.maxWaitMs) - now)) }
        }
    }

    private func flushAcks() {
        let batch = pendingAcks
        pendingAcks = []
        var groups: [(key: Keys, ids: [String])] = []
        for a in batch {
            if let i = groups.firstIndex(where: { $0.key.code == a.key.code }) { groups[i].ids.append(a.id) } else { groups.append((a.key, [a.id])) }
        }
        for (k, ids) in groups {
            let rc = k.receipts
            for b in Receipt.batches(ids) {
                let id = Packet.newId(mailbox: rc.mailbox), ts = Int64(Date().timeIntervalSince1970 * 1000)
                guard let c = try? rc.seal(id: id, ts: ts, sender: k.me, name: name, text: Receipt.text(for: b), sign: { try k.sign($0) }) else { continue }
                let p = Packet(id: id, ts: rc.hideTime(ts, c), ttl: Self.maxTtl, cipher: c)
                idsLock.withLock { _ = receiptIds.add(id); _ = myReceipts.insert(id) }
                store.append(p)
                indexed(p, .group)
                router.publish(p)
            }
        }
    }

    private static func nowMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }
    private static func unhex(_ h: String) -> Data {
        var d = Data(), i = h.startIndex
        while i < h.endIndex { let j = h.index(i, offsetBy: 2); d.append(UInt8(h[i..<j], radix: 16) ?? 0); i = j }
        return d
    }
    private static func uptimeMs() -> Int64 { Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000) }
}

/// Someone with the code asking to be let into a group; its admins decide (spec "Joining").
struct JoinRequest: Identifiable { let id: String, name: String, pub: Data }

/// A line in the group's chat: "Marco joined", "Anna removed Marco".
struct GroupEvent: Identifiable { let ts: Int64, text: String; var id: String { "\(ts)-\(text)" } }

/// Where one of my messages is: still on this phone, given to a phone in range, or confirmed by group members.
enum Delivery: Equatable {
    case waiting, sent, delivered([Reader])
}

extension Engine {
    /// nil for other people's messages, and for my older ones that haven't gone out yet.
    func delivery(of m: Message) -> Delivery? {
        guard m.sender == deviceId else { return nil }
        if !m.isPublic, let r = deliveries.readers[m.id], !r.isEmpty { return .delivered(r) }
        if handedOff.contains(m.id) { return .sent }
        return m.ts >= startedAt ? .waiting : nil
    }
}

#if DEBUG
import UIKit

/// Debug builds only: Library/Application Support/debug.log with receive times and app state changes (no message
/// text), to check from a Mac (`devicectl device copy from ...`) whether messages arrive while the phone is locked.
enum DebugLog {
    private static let lock = NSLock()
    private static let url = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("debug.log")

    static func start() {
        DispatchQueue.main.async { write(UIApplication.shared.applicationState == .background ? "app started in background" : "app started") }
        let nc = NotificationCenter.default
        nc.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: nil) { _ in write("app in background") }
        nc.addObserver(forName: UIApplication.willEnterForegroundNotification, object: nil, queue: nil) { _ in write("app in foreground") }
        nc.addObserver(forName: UIApplication.protectedDataWillBecomeUnavailableNotification, object: nil, queue: nil) { _ in write("phone locked") }
        nc.addObserver(forName: UIApplication.protectedDataDidBecomeAvailableNotification, object: nil, queue: nil) { _ in write("phone unlocked") }
    }

    static func write(_ s: String) {
        let line = Data("\(Int64(Date().timeIntervalSince1970 * 1000)) \(s)\n".utf8)
        lock.lock(); defer { lock.unlock() }
        if let h = try? FileHandle(forWritingTo: url) {
            defer { try? h.close() }
            _ = try? h.seekToEnd(); try? h.write(contentsOf: line)
        } else {
            try? line.write(to: url)
        }
    }
}
#endif
