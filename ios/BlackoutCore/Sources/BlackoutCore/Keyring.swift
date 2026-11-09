import Foundation
import CryptoKit

/// A group's epoch secrets (spec/DESIGN-v0.6-groups.md, "Keys"): a phone reads with every one it holds and writes with
/// `current`, the highest epoch, and among two of the same epoch the one whose secret has the smaller SHA-256 (every
/// phone picks the same without talking). An epoch goes 7 days after a newer one replaced it; the current one stays.
/// Same as Android's.
public final class Keyring: @unchecked Sendable { // guarded by lock
    public final class Epoch: @unchecked Sendable {
        public let number: Int64, made: Int64, group: GroupCrypto, receipts: GroupCrypto, intros: GroupCrypto, hash: String
        /// Member ids, from the rekey that brought it.
        public let secret: Data, members: [String], admins: [String]
        /// `by`: who made it. After a removal, `removes` is who went, `code` the group's new code, `via` the code it came
        /// through, and `rank` where its maker stood among the admins of the epoch before (0 = listed first, the group's creator).
        public let code: String?, via: String?, removes: String?, by: String?, rank: Int
        /// Each sender's message keys (spec "Message keys"). Nil for an epoch older than them.
        public var messageKeys: MessageKeys?
        public init(number: Int64, made: Int64, secret: Data, members: [String] = [], admins: [String] = [],
                    code: String? = nil, via: String? = nil, removes: String? = nil, by: String? = nil, rank: Int = .max, messageKeys: MessageKeys? = nil) {
            self.messageKeys = messageKeys
            self.number = number; self.made = made; self.secret = secret; self.members = members; self.admins = admins
            self.code = code; self.via = via; self.removes = removes; self.by = by; self.rank = rank
            group = GroupCrypto.fromSecret(secret); receipts = group.receipts(); intros = group.intros()
            hash = Hex.encode(Data(SHA256.hash(data: secret)))
        }

        /// A new epoch from its random `secret`, which isn't kept: only what it derives is, each sender's message keys included.
        /// `roster`: everyone in it, even when `members` is left empty because it is kept only to read with.
        public static func fresh(number: Int64, made: Int64, secret: Data, roster: [String]? = nil, members: [String], admins: [String],
                                 code: String? = nil, via: String? = nil, removes: String? = nil, by: String? = nil, rank: Int = .max) -> Epoch {
            Epoch(number: number, made: made, secret: MessageKeys.outer(secret), members: members, admins: admins, code: code, via: via, removes: removes, by: by, rank: rank,
                  messageKeys: MessageKeys.of(secret, members: roster ?? members))
        }

        /// A packet of this epoch: with its own message key if it has one, else with the epoch's key.
        public func open(_ p: Packet) -> GroupCrypto.Opened? {
            if let keys = messageKeys, let h = group.header(p), let mk = keys.key(h.index, h.counter), var o = group.open(messageKey: mk, index: h.index, counter: h.counter, p) {
                let sender = o.message.sender.hasPrefix("web-") ? String(o.message.sender.dropFirst(4)) : o.message.sender
                guard keys.members.indices.contains(h.index), keys.members[h.index] == sender else { return nil } // sealed under someone else's position: it must not use up their key
                o.leaf = Leaf(epoch: self, index: h.index, counter: h.counter)
                return o
            }
            return group.openSigned(p)
        }
    }
    public static let keepMs: Int64 = 7 * 24 * 3_600_000, hourMs: Int64 = 3_600_000
    /// A phone waits a random time up to this after the week is up, so the group's phones don't all make a new key at once.
    public static let maxDelayMs: Int64 = 6 * 3_600_000
    public static let maxMembers = 100
    private static let maxEpochs = 64
    private static let maxEpoch: Int64 = 1 << 53
    private static let maxKeysPerHour = 4 // from one member, except admins, as they arrive here
    private var lately: [String: [Int64]] = [:] // lock: maker -> when this phone took their last new keys

    /// True if `maker` brought `maxKeysPerHour` new keys in the last hour by this phone's clock: the date in a key is whatever its maker wrote. Hold the lock.
    private func manyLately(_ maker: String, _ now: Int64) -> Bool { (lately[maker] ?? []).filter { now - $0 < Self.hourMs }.count >= Self.maxKeysPerHour }

    /// Hold the lock.
    private func arrived(_ maker: String, _ now: Int64) {
        if lately.count > Self.maxMembers * 4 { lately = [:] } // only limits a flood: forgetting is harmless
        lately[maker, default: []].append(now)
        if lately[maker]!.count > Self.maxKeysPerHour { lately[maker]!.removeFirst() }
    }

    /// The epochs that say who is in and who decides, from those `earlier` numbered just before a key: not one kept only
    /// for reading, which a member can write with any list they like and so would make themselves an admin; else `cur`.
    private func counting(_ earlier: [Epoch], _ cur: Epoch) -> [Epoch] {
        let real = earlier.filter { !$0.members.isEmpty }
        return real.isEmpty ? [cur] : real
    }

    /// True if rules about how often a member may make a key don't apply to `r`: admins. Hold the lock.
    private func exempt(_ r: Rekey, _ maker: String) -> Bool {
        guard let cur = pick() else { return true }
        let before = counting(list.filter { $0.number == r.epoch &- 1 }.sorted(by: Self.first), cur)
        return before.contains { $0.admins.contains(maker) }
    }

    private static let maxJump: Int64 = 1000             // how far ahead of this phone's epoch a rekey may be numbered
    private static let maxAheadMs: Int64 = 10 * 60_000   // clocks differ; a date further ahead would put off the weekly key

    /// True if an epoch made at `made` is due for its weekly replacement on a phone whose random delay is `delay`.
    public static func weeklyDue(made: Int64, now: Int64, delay: Int64) -> Bool { now >= made + keepMs + delay }
    /// True if the epoch is past every phone's delay: this phone missed the group's new key, or the whole group was quiet.
    public static func overdue(made: Int64, now: Int64) -> Bool { now >= made + keepMs + maxDelayMs }

    private let lock = NSLock()
    private var list: [Epoch] = []

    public init() {}

    /// False if this secret was there already.
    @discardableResult public func add(_ e: Epoch) -> Bool {
        lock.withLock {
            if list.contains(where: { $0.hash == e.hash }) { return false }
            list.append(e)
            if list.count > Self.maxEpochs, let worst = list.max(by: Self.first) { list.removeAll { $0 === worst } } // every packet is tried with each of them: a flood can't make that endless
            return true
        }
    }

    public var current: Epoch { lock.withLock { pick()! } }
    public var currentOrNil: Epoch? { lock.withLock { pick() } }

    /// Every epoch, the current one first: the order phones try them in.
    public var all: [Epoch] { lock.withLock { guard let c = pick() else { return [] }; return [c] + list.filter { $0 !== c } } }

    /// Drops the epochs replaced more than 7 days before `now`, never the current one; returns what went. Counted from
    /// the next epoch, not this one: a message written on its last day can still arrive a week later.
    @discardableResult public func expire(now: Int64) -> [Epoch] {
        lock.withLock {
            guard let c = pick() else { return [] }
            let gone = list.filter { e in
                guard e !== c, let next = list.filter({ $0.number > e.number }).map(\.made).min() else { return false }
                return Swift.max(next, e.made) < now - Self.keepMs
            }
            list.removeAll { e in gone.contains { $0 === e } }
            return gone
        }
    }

    /// True if removal `e` is now the one to follow: the newest, or a late one that beat the rival this phone had followed.
    public func leads(_ e: Epoch) -> Bool {
        lock.withLock { isWinner(e) && (lastMoved() === e || list.contains { $0 !== e && $0.code != nil && $0.number == e.number }) }
    }

    /// People a removal that lost took out, who are still in the current epoch: an admin's phone finishes the job.
    public func stillToRemove() -> [String] {
        lock.withLock {
            guard let cur = pick() else { return [] }
            let gone = Set(Set(list.filter { $0.code != nil }.map(\.number)).flatMap { goneAt($0) })
            return cur.members.filter(gone.contains)
        }
    }

    /// Admins added by rekeys of the current number that didn't win: the next rekey an admin makes keeps them.
    public func rivalAdmins() -> [String] {
        lock.withLock {
            guard let cur = pick() else { return [] }
            let gone = goneAt(cur.number)
            var out: [String] = []
            for e in list where e.number == cur.number && e !== cur && !(e.by.map(gone.contains) ?? false) {
                for a in e.admins where !cur.admins.contains(a) && !gone.contains(a) && !out.contains(a) { out.append(a) }
            }
            return out
        }
    }

    /// Who the removals numbered `number` took out, most senior admin first. A removal by someone a more senior one removed doesn't count.
    private func goneAt(_ number: Int64) -> Set<String> {
        var out = Set<String>()
        for e in list.filter({ $0.code != nil && $0.number == number }).sorted(by: Self.first) where !(e.by.map(out.contains) ?? false) {
            if let r = e.removes { out.insert(r) }
        }
        return out
    }

    /// What a phone does with a rekey whose signature checked out.
    public enum Taken {
        /// Not allowed, or nothing for this phone.
        case ignored
        /// This phone was removed: that removal's epoch number and its maker's rank.
        case removed(number: Int64, rank: Int)
        /// This phone is still joining and a removal went past without it: its code no longer works.
        case closed
        /// A new epoch. `moveTo`: the code the group follows now. `back`: a removal that outranks the one that removed this phone.
        case added(Epoch, moveTo: String?, back: Bool)
    }

    /// The whole decision about rekey `r` (spec "New key"), the same on both apps so that phones given the same rekeys
    /// in any order agree. `door`: the code it came through; `oldDoor`: the group has moved on from that code. `me`: this
    /// phone's member id. `removedAt`: the removal that removed this phone. `pinned`: its maker is one the invite named, or
    /// the invite named nobody. `open` opens this phone's sealed part.
    public func take(_ r: Rekey, maker: String, me: String, door: String, oldDoor: Bool, removedAt: (number: Int64, rank: Int)?,
                     now: Int64 = Int64(Date().timeIntervalSince1970 * 1000), pinned: Bool = true, open: (Data) -> Data?) -> Taken {
        let seniority = rank(r, maker: maker), mine = r.parts.first { $0.id == me }
        if mine == nil && r.members.contains(me) { return .ignored } // this phone's part is in another packet of the same key
        if let at = removedAt, !(r.removal && r.epoch == at.number && seniority < at.rank && mine != nil) { return .ignored }
        guard let admins = admit(r, maker: maker, oldDoor: oldDoor ? door : nil, now: now, pinned: pinned) else { return .ignored }
        let cur = currentOrNil
        if r.removal, r.answers == me, let cur, r.epoch >= cur.number, !outranked(r, maker: maker) { return .removed(number: r.epoch, rank: seniority) } // a later rejoin has a higher epoch
        guard let mine else { return r.removal && cur == nil ? .closed : .ignored }
        // unbox checks the shape: anyone with the code can seal a part, and a wrong-sized secret must not reach fromSecret.
        guard let plain = open(mine.box), let opened = Rekey.unbox(plain, removal: r.removal) else { return .ignored }
        // Numbered below the current epoch: it opens old messages and proves nothing about who is in. Except a removal,
        // which can become the current epoch again even when it arrives late, and which only an admin can make.
        let forReadingOnly = !r.removal && cur.map { r.epoch < $0.number } ?? false
        let e = Epoch.fresh(number: r.epoch, made: r.made, secret: opened.secret, roster: r.members, members: forReadingOnly ? [] : r.members, admins: admins, code: opened.code,
                      via: r.removal ? door : nil, removes: r.removal ? r.answers : nil, by: maker, rank: r.removal ? seniority : .max)
        let counted = lock.withLock { !exempt(r, maker) }
        guard add(e) else { return .ignored }
        if counted { lock.withLock { arrived(maker, now) } }
        let follow = opened.code != nil && leads(e)
        if follow { dropAbove(e.number) }
        return .added(e, moveTo: follow ? opened.code : nil, back: removedAt != nil)
    }

    /// True if `maker` already made an epoch within an hour of `made`.
    public func tooSoon(_ maker: String, made: Int64) -> Bool { lock.withLock { madeWithinAnHour(maker, made) } }

    /// True if member `maker` made `r` after this phone's current epoch but numbered it lower: their phone missed our keys.
    public func behind(_ r: Rekey, maker: String) -> Bool {
        lock.withLock { guard let c = pick() else { return false }; return !r.removal && r.epoch < c.number && r.made > c.made && c.members.contains(maker) }
    }

    /// The newest removal: its code is the one the group follows.
    public var lastMove: Epoch? { lock.withLock { lastMoved() } }

    /// After a removal: anything numbered above it was made through the old door by someone who hadn't heard.
    public func dropAbove(_ number: Int64) { lock.withLock { list.removeAll { $0.number > number } } }

    /// True if `id` was removed before `ts`: what a removed member writes afterwards isn't shown. A removal that lost doesn't count.
    public func removed(_ id: String, before ts: Int64) -> Bool { lock.withLock { list.contains { $0.removes == id && ts > $0.made && isWinner($0) } } }

    /// True if no other epoch with `e`'s number comes before it.
    public func won(_ e: Epoch) -> Bool { lock.withLock { isWinner(e) } }

    /// Where `maker` stood among the admins of the epoch before `r`: the lower, the more senior.
    public func rank(_ r: Rekey, maker: String) -> Int { lock.withLock { rankOf(r, maker) } }

    /// True if a removal this phone holds outranks `r`, so `r` can't take effect.
    public func outranked(_ r: Rekey, maker: String) -> Bool {
        lock.withLock { let mine = rankOf(r, maker); return list.contains { $0.code != nil && $0.number == r.epoch && $0.rank < mine } }
    }

    /// The admins rekey `r` gives its epoch on this phone, or nil if it must be ignored (spec "New key"). `maker` is
    /// its checked signer; `oldDoor`: the code it came through if the group has moved on from it, else nil.
    /// - A phone still joining takes the first one that includes it, from an admin its invite named (`pinned`). With a typed
    ///   code it has nothing better to trust than the code.
    /// - Only admins of the epoch before it may leave people out, change the admins or remove someone. A removal needs
    ///   that epoch here: picking a higher number can't put it ahead of a removal that outranks it.
    /// - Through an old door only a rival removal counts, numbered the same as the removal this phone followed out of it,
    ///   or a key numbered below that one, which arrived late.
    /// - Older than the current epoch: kept only to read with, so it can't change who is in, and only from someone who
    ///   has been a member, or anyone with an old code could fill the phone with keys.
    /// - At most one per member per hour, except admins' and rekeys that let someone new in.
    /// - Numbers and times that make no sense, and groups over `maxMembers`, are refused.
    public func admit(_ r: Rekey, maker: String, oldDoor: String?, now: Int64 = Int64(Date().timeIntervalSince1970 * 1000), pinned: Bool = true) -> [String]? {
        guard (1...Self.maxEpoch).contains(r.epoch), r.made >= 0, r.made <= now + Self.maxAheadMs, r.members.count <= Self.maxMembers else { return nil }
        return lock.withLock {
            guard let cur = pick() else { return oldDoor == nil && pinned ? r.admins : nil }
            if r.epoch > cur.number + Self.maxJump { return nil }
            let earlier = list.filter { $0.number == r.epoch - 1 }.sorted(by: Self.first)
            if r.removal && earlier.isEmpty { return nil }
            let before = counting(earlier, cur)
            let byAdmin = before.contains { $0.admins.contains(maker) }
            if r.removal && (!byAdmin || r.answers.map { r.members.contains($0) } != false) { return nil }
            if let oldDoor {
                guard let left = list.filter({ $0.code != nil && $0.via == oldDoor }).min(by: Self.first) else { return nil }
                if r.removal ? left.number != r.epoch : r.epoch >= left.number { return nil }
            }
            if !byAdmin && (madeWithinAnHour(maker, r.made) || manyLately(maker, now)) { return nil }
            let knownMaker = list.contains { $0.members.contains(maker) }
            if r.epoch < cur.number { return knownMaker ? (byAdmin ? r.admins : before[0].admins) : nil }
            if !byAdmin && (!before[0].members.contains(maker) || Set(before[0].members) != Set(r.members)) { return nil }
            return byAdmin ? r.admins : before[0].admins
        }
    }

    /// Highest number first. For the same number a removal beats anything else (or the removed person would still be
    /// in), then the most senior admin's removal: its maker can't choose that, as they could a hash. Then the smallest hash.
    private static func first(_ a: Epoch, _ b: Epoch) -> Bool {
        if a.number != b.number { return a.number > b.number }
        if (a.code == nil) != (b.code == nil) { return a.code != nil }
        if a.rank != b.rank { return a.rank < b.rank }
        return a.hash < b.hash
    }
    private func isWinner(_ e: Epoch) -> Bool { !list.contains { $0 !== e && $0.number == e.number && Self.first($0, e) } }
    private func madeWithinAnHour(_ maker: String, _ made: Int64) -> Bool { list.contains { $0.by == maker && abs($0.made - made) < Self.hourMs } }
    private func rankOf(_ r: Rekey, _ maker: String) -> Int { // runs before admit has checked r: wrapping subtraction, so a crafted number can't crash
        list.filter { $0.number == r.epoch &- 1 }.compactMap { $0.admins.firstIndex(of: maker) }.min() ?? .max
    }
    private func pick() -> Epoch? { list.min(by: Self.first) }
    private func lastMoved() -> Epoch? { list.filter { $0.code != nil }.min(by: Self.first) }
}
