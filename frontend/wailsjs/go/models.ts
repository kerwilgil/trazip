export namespace api {
	
	export class AddrReport {
	    addr: string;
	    family: string;
	    classes: string[];
	    isPublic: boolean;
	    reachable?: boolean;
	    country?: string;
	    countryCode?: string;
	    city?: string;
	    asn?: number;
	    org?: string;
	    lat?: number;
	    lon?: number;
	    netClass?: netclass.Match;
	    static createFrom(source: any = {}) {
	        return new AddrReport(source);
	    }
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.addr = source["addr"];
	        this.family = source["family"];
	        this.classes = source["classes"];
	        this.isPublic = source["isPublic"];
	        this.reachable = source["reachable"];
	        this.country = source["country"];
	        this.countryCode = source["countryCode"];
	        this.city = source["city"];
	        this.asn = source["asn"];
	        this.org = source["org"];
	        this.lat = source["lat"];
	        this.lon = source["lon"];
	        this.netClass = this.convertValues(source["netClass"], netclass.Match);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Capabilities {
	    platform: string;
	    arch: string;
	    elevated: boolean;
	    liveCapture: boolean;
	    captureNote: string;
	    rawSockets: boolean;
	    version: string;
	    portable: boolean;
	    dataDir: string;
	
	    static createFrom(source: any = {}) {
	        return new Capabilities(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.platform = source["platform"];
	        this.arch = source["arch"];
	        this.elevated = source["elevated"];
	        this.liveCapture = source["liveCapture"];
	        this.captureNote = source["captureNote"];
	        this.rawSockets = source["rawSockets"];
	        this.version = source["version"];
	        this.portable = source["portable"];
	        this.dataDir = source["dataDir"];
	    }
	}
	export class ConnRow {
	    proto: string;
	    localAddr: string;
	    localPort: number;
	    remoteAddr: string;
	    remotePort: number;
	    state?: string;
	    pid?: number;
	    process?: string;
	    remote?: AddrReport;
	
	    static createFrom(source: any = {}) {
	        return new ConnRow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.proto = source["proto"];
	        this.localAddr = source["localAddr"];
	        this.localPort = source["localPort"];
	        this.remoteAddr = source["remoteAddr"];
	        this.remotePort = source["remotePort"];
	        this.state = source["state"];
	        this.pid = source["pid"];
	        this.process = source["process"];
	        this.remote = this.convertValues(source["remote"], AddrReport);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ConnMonSnapshot {
	    connections: ConnRow[];
	    total: number;
	
	    static createFrom(source: any = {}) {
	        return new ConnMonSnapshot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.connections = this.convertValues(source["connections"], ConnRow);
	        this.total = source["total"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class DiagnoseResult {
	    input: string;
	    kind: string;
	    host?: string;
	    addrs: AddrReport[];
	    notes?: string[];
	    durationMs: number;
	
	    static createFrom(source: any = {}) {
	        return new DiagnoseResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.input = source["input"];
	        this.kind = source["kind"];
	        this.host = source["host"];
	        this.addrs = this.convertValues(source["addrs"], AddrReport);
	        this.notes = source["notes"];
	        this.durationMs = source["durationMs"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class EvidenceInfo {
	    type: string;
	    value: string;
	    source: string;
	    provenance: string;
	    timestamp: string;
	    confidence: number;
	    explain?: string;
	
	    static createFrom(source: any = {}) {
	        return new EvidenceInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.value = source["value"];
	        this.source = source["source"];
	        this.provenance = source["provenance"];
	        this.timestamp = source["timestamp"];
	        this.confidence = source["confidence"];
	        this.explain = source["explain"];
	    }
	}
	export class EndpointInfo {
	    addr: string;
	    classes?: string[];
	    firstSeen?: string;
	    lastSeen?: string;
	    packets: number;
	    bytes: number;
	    country?: string;
	    countryCode?: string;
	    city?: string;
	    asn?: number;
	    org?: string;
	    evidence: EvidenceInfo[];
	
	    static createFrom(source: any = {}) {
	        return new EndpointInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.addr = source["addr"];
	        this.classes = source["classes"];
	        this.firstSeen = source["firstSeen"];
	        this.lastSeen = source["lastSeen"];
	        this.packets = source["packets"];
	        this.bytes = source["bytes"];
	        this.country = source["country"];
	        this.countryCode = source["countryCode"];
	        this.city = source["city"];
	        this.asn = source["asn"];
	        this.org = source["org"];
	        this.evidence = this.convertValues(source["evidence"], EvidenceInfo);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class InvestigationAddResult {
	    entry: investigation.Entry;
	    existing: boolean;
	
	    static createFrom(source: any = {}) {
	        return new InvestigationAddResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.entry = this.convertValues(source["entry"], investigation.Entry);
	        this.existing = source["existing"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class MonitorTargetInfo {
	    target: monitor.Target;
	    running: boolean;
	
	    static createFrom(source: any = {}) {
	        return new MonitorTargetInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = this.convertValues(source["target"], monitor.Target);
	        this.running = source["running"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PassiveOSINTResult {
	    input: string;
	    host: string;
	    external: boolean;
	    addresses: AddrReport[];
	    rdap?: rdap.Result;
	    notes?: string[];
	    queriedAt?: string;
	    dataSent?: string;
	
	    static createFrom(source: any = {}) {
	        return new PassiveOSINTResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.input = source["input"];
	        this.host = source["host"];
	        this.external = source["external"];
	        this.addresses = this.convertValues(source["addresses"], AddrReport);
	        this.rdap = this.convertValues(source["rdap"], rdap.Result);
	        this.notes = source["notes"];
	        this.queriedAt = source["queriedAt"];
	        this.dataSent = source["dataSent"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TalkerRow {
	    key: string;
	    label: string;
	    packets: number;
	    bytes: number;
	    country?: string;
	    asn?: number;
	    org?: string;
	
	    static createFrom(source: any = {}) {
	        return new TalkerRow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.label = source["label"];
	        this.packets = source["packets"];
	        this.bytes = source["bytes"];
	        this.country = source["country"];
	        this.asn = source["asn"];
	        this.org = source["org"];
	    }
	}
	export class PcapResult {
	    info: pcap.Info;
	    packets: packet.Summary[];
	    flows: flow.Flow[];
	    totalPackets: number;
	    shownPackets: number;
	    totalFlows: number;
	    topHosts: TalkerRow[];
	    topCountries: TalkerRow[];
	    topASN: TalkerRow[];
	    geoAvailable: boolean;
	    endpoints: EndpointInfo[];
	    totalEndpoints: number;
	    scanDetection: scandetect.Result;
	    netDiag: netdiag.Result;
	    summary: correlation.PcapIncidentSummary;
	
	    static createFrom(source: any = {}) {
	        return new PcapResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.info = this.convertValues(source["info"], pcap.Info);
	        this.packets = this.convertValues(source["packets"], packet.Summary);
	        this.flows = this.convertValues(source["flows"], flow.Flow);
	        this.totalPackets = source["totalPackets"];
	        this.shownPackets = source["shownPackets"];
	        this.totalFlows = source["totalFlows"];
	        this.topHosts = this.convertValues(source["topHosts"], TalkerRow);
	        this.topCountries = this.convertValues(source["topCountries"], TalkerRow);
	        this.topASN = this.convertValues(source["topASN"], TalkerRow);
	        this.geoAvailable = source["geoAvailable"];
	        this.endpoints = this.convertValues(source["endpoints"], EndpointInfo);
	        this.totalEndpoints = source["totalEndpoints"];
	        this.scanDetection = this.convertValues(source["scanDetection"], scandetect.Result);
	        this.netDiag = this.convertValues(source["netDiag"], netdiag.Result);
	        this.summary = this.convertValues(source["summary"], correlation.PcapIncidentSummary);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PublicIPResult {
	    ip: string;
	    family: number;
	    source: string;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new PublicIPResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.family = source["family"];
	        this.source = source["source"];
	        this.err = source["err"];
	    }
	}
	export class SelfTestCheck {
	    id: string;
	    label: string;
	    status: string;
	    detail?: string;
	    durationMs: number;
	
	    static createFrom(source: any = {}) {
	        return new SelfTestCheck(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.label = source["label"];
	        this.status = source["status"];
	        this.detail = source["detail"];
	        this.durationMs = source["durationMs"];
	    }
	}
	export class SelfTestResult {
	    mode: string;
	    startedAt: string;
	    completedAt: string;
	    overallStatus: string;
	    checks: SelfTestCheck[];
	    passed: number;
	    failed: number;
	    skipped: number;
	    unavailable: number;
	    networkOut: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SelfTestResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mode = source["mode"];
	        this.startedAt = source["startedAt"];
	        this.completedAt = source["completedAt"];
	        this.overallStatus = source["overallStatus"];
	        this.checks = this.convertValues(source["checks"], SelfTestCheck);
	        this.passed = source["passed"];
	        this.failed = source["failed"];
	        this.skipped = source["skipped"];
	        this.unavailable = source["unavailable"];
	        this.networkOut = source["networkOut"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Service {
	
	
	    static createFrom(source: any = {}) {
	        return new Service(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class SessionInfo {
	    id: string;
	    label: string;
	    state: string;
	    created: string;
	    scopeLabel: string;
	    authorized: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SessionInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.label = source["label"];
	        this.state = source["state"];
	        this.created = source["created"];
	        this.scopeLabel = source["scopeLabel"];
	        this.authorized = source["authorized"];
	    }
	}

}

export namespace bgp {
	
	export class ComponentEvidence {
	    component: string;
	    status: string;
	    disclosure: external.Disclosure;
	    fromCache: boolean;
	    err?: string;
	    sourceEventIds?: string[];
	
	    static createFrom(source: any = {}) {
	        return new ComponentEvidence(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.component = source["component"];
	        this.status = source["status"];
	        this.disclosure = this.convertValues(source["disclosure"], external.Disclosure);
	        this.fromCache = source["fromCache"];
	        this.err = source["err"];
	        this.sourceEventIds = source["sourceEventIds"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class NeighbourObservation {
	    asn: number;
	    position: string;
	    rawPosition: string;
	    pathCount: number;
	    peerCountV4: number;
	    peerCountV6: number;
	
	    static createFrom(source: any = {}) {
	        return new NeighbourObservation(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.asn = source["asn"];
	        this.position = source["position"];
	        this.rawPosition = source["rawPosition"];
	        this.pathCount = source["pathCount"];
	        this.peerCountV4 = source["peerCountV4"];
	        this.peerCountV6 = source["peerCountV6"];
	    }
	}
	export class NeighbourCounts {
	    left: number;
	    right: number;
	    unique: number;
	    uncertain: number;
	
	    static createFrom(source: any = {}) {
	        return new NeighbourCounts(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.left = source["left"];
	        this.right = source["right"];
	        this.unique = source["unique"];
	        this.uncertain = source["uncertain"];
	    }
	}
	export class ASNNeighboursResult {
	    resource: string;
	    queryTime?: string;
	    neighbourCounts: NeighbourCounts;
	    neighbours: NeighbourObservation[];
	    evidence: ComponentEvidence;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new ASNNeighboursResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.resource = source["resource"];
	        this.queryTime = source["queryTime"];
	        this.neighbourCounts = this.convertValues(source["neighbourCounts"], NeighbourCounts);
	        this.neighbours = this.convertValues(source["neighbours"], NeighbourObservation);
	        this.evidence = this.convertValues(source["evidence"], ComponentEvidence);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ASNObservatoryRequest {
	    ASN: string;
	
	    static createFrom(source: any = {}) {
	        return new ASNObservatoryRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ASN = source["ASN"];
	    }
	}
	export class ASNObservatoryResult {
	    asn: number;
	    announcedIPv4Prefixes: number;
	    announcedIPv6Prefixes: number;
	    dataSufficient: boolean;
	    evidence: ComponentEvidence[];
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new ASNObservatoryResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.asn = source["asn"];
	        this.announcedIPv4Prefixes = source["announcedIPv4Prefixes"];
	        this.announcedIPv6Prefixes = source["announcedIPv6Prefixes"];
	        this.dataSufficient = source["dataSufficient"];
	        this.evidence = this.convertValues(source["evidence"], ComponentEvidence);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class AnnouncedSpaceV4 {
	    prefixes: number;
	    ips: number;
	
	    static createFrom(source: any = {}) {
	        return new AnnouncedSpaceV4(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.prefixes = source["prefixes"];
	        this.ips = source["ips"];
	    }
	}
	export class AnnouncedSpaceV6 {
	    prefixes: number;
	    slash48s: number;
	
	    static createFrom(source: any = {}) {
	        return new AnnouncedSpaceV6(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.prefixes = source["prefixes"];
	        this.slash48s = source["slash48s"];
	    }
	}
	export class BGPHistoryRequest {
	    Resource: string;
	    StartTime: string;
	    EndTime: string;
	
	    static createFrom(source: any = {}) {
	        return new BGPHistoryRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Resource = source["Resource"];
	        this.StartTime = source["StartTime"];
	        this.EndTime = source["EndTime"];
	    }
	}
	export class BGPHistoryUpdate {
	    Seq: number;
	    Timestamp: string;
	    Type: string;
	    SourceID: string;
	    targetPrefix: string;
	    path?: number[];
	    community?: string[];
	
	    static createFrom(source: any = {}) {
	        return new BGPHistoryUpdate(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Seq = source["Seq"];
	        this.Timestamp = source["Timestamp"];
	        this.Type = source["Type"];
	        this.SourceID = source["SourceID"];
	        this.targetPrefix = source["targetPrefix"];
	        this.path = source["path"];
	        this.community = source["community"];
	    }
	}
	export class BGPHistoryResult {
	    Resource: string;
	    StartTime: string;
	    EndTime: string;
	    updates: BGPHistoryUpdate[];
	    truncated: boolean;
	    observedUpdates: number;
	    evidence: ComponentEvidence[];
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new BGPHistoryResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Resource = source["Resource"];
	        this.StartTime = source["StartTime"];
	        this.EndTime = source["EndTime"];
	        this.updates = this.convertValues(source["updates"], BGPHistoryUpdate);
	        this.truncated = source["truncated"];
	        this.observedUpdates = source["observedUpdates"];
	        this.evidence = this.convertValues(source["evidence"], ComponentEvidence);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class BGPlayNode {
	    ASN: number;
	    Owner: string;
	
	    static createFrom(source: any = {}) {
	        return new BGPlayNode(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ASN = source["ASN"];
	        this.Owner = source["Owner"];
	    }
	}
	export class BGPlayPath {
	    SourceID: string;
	    TargetPrefix: string;
	    Path: number[];
	    Community: string[];
	
	    static createFrom(source: any = {}) {
	        return new BGPlayPath(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.SourceID = source["SourceID"];
	        this.TargetPrefix = source["TargetPrefix"];
	        this.Path = source["Path"];
	        this.Community = source["Community"];
	    }
	}
	export class BGPlayRequest {
	    Resource: string;
	    StartTime: string;
	    EndTime: string;
	
	    static createFrom(source: any = {}) {
	        return new BGPlayRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Resource = source["Resource"];
	        this.StartTime = source["StartTime"];
	        this.EndTime = source["EndTime"];
	    }
	}
	export class BGPlaySource {
	    ASN: number;
	    ID: string;
	    IP: string;
	    RRC: string;
	
	    static createFrom(source: any = {}) {
	        return new BGPlaySource(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ASN = source["ASN"];
	        this.ID = source["ID"];
	        this.IP = source["IP"];
	        this.RRC = source["RRC"];
	    }
	}
	export class BGPlayResult {
	    Resource: string;
	    StartTime: string;
	    EndTime: string;
	    initialState: BGPlayPath[];
	    events: BGPHistoryUpdate[];
	    nodes: BGPlayNode[];
	    sources: BGPlaySource[];
	    truncated: boolean;
	    observedInitialState: number;
	    observedEvents: number;
	    observedNodes: number;
	    evidence: ComponentEvidence[];
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new BGPlayResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Resource = source["Resource"];
	        this.StartTime = source["StartTime"];
	        this.EndTime = source["EndTime"];
	        this.initialState = this.convertValues(source["initialState"], BGPlayPath);
	        this.events = this.convertValues(source["events"], BGPHistoryUpdate);
	        this.nodes = this.convertValues(source["nodes"], BGPlayNode);
	        this.sources = this.convertValues(source["sources"], BGPlaySource);
	        this.truncated = source["truncated"];
	        this.observedInitialState = source["observedInitialState"];
	        this.observedEvents = source["observedEvents"];
	        this.observedNodes = source["observedNodes"];
	        this.evidence = this.convertValues(source["evidence"], ComponentEvidence);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class BogonLookupRequest {
	    Resource: string;
	
	    static createFrom(source: any = {}) {
	        return new BogonLookupRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Resource = source["Resource"];
	    }
	}
	export class IANASpecialPurposeMatch {
	    prefix: string;
	    name: string;
	    rfc: string;
	    allocationDate: string;
	    terminationDate: string;
	    source?: boolean;
	    destination?: boolean;
	    forwardable?: boolean;
	    globallyReachable?: boolean;
	    reservedByProtocol?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new IANASpecialPurposeMatch(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.prefix = source["prefix"];
	        this.name = source["name"];
	        this.rfc = source["rfc"];
	        this.allocationDate = source["allocationDate"];
	        this.terminationDate = source["terminationDate"];
	        this.source = source["source"];
	        this.destination = source["destination"];
	        this.forwardable = source["forwardable"];
	        this.globallyReachable = source["globallyReachable"];
	        this.reservedByProtocol = source["reservedByProtocol"];
	    }
	}
	export class BogonLookupResult {
	    resource: string;
	    resourceKind: string;
	    family: number;
	    ianaSpecialPurpose?: boolean;
	    ianaMatch?: IANASpecialPurposeMatch;
	    cymruFullBogon?: boolean;
	    cymruMatchPrefix?: string;
	    dataSufficient: boolean;
	    evidence: ComponentEvidence[];
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new BogonLookupResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.resource = source["resource"];
	        this.resourceKind = source["resourceKind"];
	        this.family = source["family"];
	        this.ianaSpecialPurpose = source["ianaSpecialPurpose"];
	        this.ianaMatch = this.convertValues(source["ianaMatch"], IANASpecialPurposeMatch);
	        this.cymruFullBogon = source["cymruFullBogon"];
	        this.cymruMatchPrefix = source["cymruMatchPrefix"];
	        this.dataSufficient = source["dataSufficient"];
	        this.evidence = this.convertValues(source["evidence"], ComponentEvidence);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class CountryObservatoryPoint {
	    statsData: string;
	    startTime: string;
	    endTime: string;
	    asnsRis: number;
	    asnsRegistered: number;
	    ipv4PrefixesRis: number;
	    ipv4PrefixesRegistered: number;
	    ipv6PrefixesRis: number;
	    ipv6PrefixesRegistered: number;
	
	    static createFrom(source: any = {}) {
	        return new CountryObservatoryPoint(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.statsData = source["statsData"];
	        this.startTime = source["startTime"];
	        this.endTime = source["endTime"];
	        this.asnsRis = source["asnsRis"];
	        this.asnsRegistered = source["asnsRegistered"];
	        this.ipv4PrefixesRis = source["ipv4PrefixesRis"];
	        this.ipv4PrefixesRegistered = source["ipv4PrefixesRegistered"];
	        this.ipv6PrefixesRis = source["ipv6PrefixesRis"];
	        this.ipv6PrefixesRegistered = source["ipv6PrefixesRegistered"];
	    }
	}
	export class CountryObservatoryRequest {
	    Country: string;
	    StartTime: string;
	    EndTime: string;
	    Resolution: string;
	
	    static createFrom(source: any = {}) {
	        return new CountryObservatoryRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Country = source["Country"];
	        this.StartTime = source["StartTime"];
	        this.EndTime = source["EndTime"];
	        this.Resolution = source["Resolution"];
	    }
	}
	export class CountryObservatoryResult {
	    country: string;
	    startTime: string;
	    endTime: string;
	    resolution: string;
	    queryStartTime: string;
	    queryEndTime: string;
	    earliestTime: string;
	    latestTime: string;
	    hdLatestTime: string;
	    points: CountryObservatoryPoint[];
	    dataSufficient: boolean;
	    evidence: ComponentEvidence[];
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new CountryObservatoryResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.country = source["country"];
	        this.startTime = source["startTime"];
	        this.endTime = source["endTime"];
	        this.resolution = source["resolution"];
	        this.queryStartTime = source["queryStartTime"];
	        this.queryEndTime = source["queryEndTime"];
	        this.earliestTime = source["earliestTime"];
	        this.latestTime = source["latestTime"];
	        this.hdLatestTime = source["hdLatestTime"];
	        this.points = this.convertValues(source["points"], CountryObservatoryPoint);
	        this.dataSufficient = source["dataSufficient"];
	        this.evidence = this.convertValues(source["evidence"], ComponentEvidence);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Edge {
	    from: number;
	    to: number;
	    observationCount: number;
	
	    static createFrom(source: any = {}) {
	        return new Edge(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.from = source["from"];
	        this.to = source["to"];
	        this.observationCount = source["observationCount"];
	    }
	}
	export class GlobalRISObservatoryResult {
	    visibleAsns?: number;
	    asnsQueryTime?: string;
	    risPeersIPv4Total?: number;
	    risPeersIPv4FullFeed?: number;
	    risPeersIPv6Total?: number;
	    risPeersIPv6FullFeed?: number;
	    peersStartTime?: string;
	    peersEndTime?: string;
	    dataSufficient: boolean;
	    evidence: ComponentEvidence[];
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new GlobalRISObservatoryResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.visibleAsns = source["visibleAsns"];
	        this.asnsQueryTime = source["asnsQueryTime"];
	        this.risPeersIPv4Total = source["risPeersIPv4Total"];
	        this.risPeersIPv4FullFeed = source["risPeersIPv4FullFeed"];
	        this.risPeersIPv6Total = source["risPeersIPv6Total"];
	        this.risPeersIPv6FullFeed = source["risPeersIPv6FullFeed"];
	        this.peersStartTime = source["peersStartTime"];
	        this.peersEndTime = source["peersEndTime"];
	        this.dataSufficient = source["dataSufficient"];
	        this.evidence = this.convertValues(source["evidence"], ComponentEvidence);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class RPKIEvidence {
	    prefix: string;
	    state: string;
	
	    static createFrom(source: any = {}) {
	        return new RPKIEvidence(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.prefix = source["prefix"];
	        this.state = source["state"];
	    }
	}
	export class Node {
	    asn: number;
	    displayName?: string;
	    observedRole: string;
	    originRpki?: RPKIEvidence;
	    pathCount: number;
	
	    static createFrom(source: any = {}) {
	        return new Node(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.asn = source["asn"];
	        this.displayName = source["displayName"];
	        this.observedRole = source["observedRole"];
	        this.originRpki = this.convertValues(source["originRpki"], RPKIEvidence);
	        this.pathCount = source["pathCount"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Graph {
	    resource: string;
	    timestamp?: string;
	    nodes: Node[];
	    edges: Edge[];
	    routes?: string[];
	    observedRoutes: number;
	    observedNodes: number;
	    observedEdges: number;
	    viewTruncated: boolean;
	    evidence: ComponentEvidence[];
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new Graph(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.resource = source["resource"];
	        this.timestamp = source["timestamp"];
	        this.nodes = this.convertValues(source["nodes"], Node);
	        this.edges = this.convertValues(source["edges"], Edge);
	        this.routes = source["routes"];
	        this.observedRoutes = source["observedRoutes"];
	        this.observedNodes = source["observedNodes"];
	        this.observedEdges = source["observedEdges"];
	        this.viewTruncated = source["viewTruncated"];
	        this.evidence = this.convertValues(source["evidence"], ComponentEvidence);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class HealthRule {
	    id: string;
	    fired: boolean;
	    detail: string;
	    applicable: boolean;
	
	    static createFrom(source: any = {}) {
	        return new HealthRule(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.fired = source["fired"];
	        this.detail = source["detail"];
	        this.applicable = source["applicable"];
	    }
	}
	export class HealthResult {
	    state: string;
	    rules: HealthRule[];
	    dataSufficient: boolean;
	
	    static createFrom(source: any = {}) {
	        return new HealthResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.state = source["state"];
	        this.rules = this.convertValues(source["rules"], HealthRule);
	        this.dataSufficient = source["dataSufficient"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	export class NeighborsSummary {
	    count: number;
	    left: number;
	    right: number;
	    uncertain: number;
	    unknown: number;
	    observations?: NeighbourObservation[];
	
	    static createFrom(source: any = {}) {
	        return new NeighborsSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.count = source["count"];
	        this.left = source["left"];
	        this.right = source["right"];
	        this.uncertain = source["uncertain"];
	        this.unknown = source["unknown"];
	        this.observations = this.convertValues(source["observations"], NeighbourObservation);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	export class RPKIValidationROA {
	    origin: string;
	    prefix: string;
	    maxLength: number;
	    validity: string;
	
	    static createFrom(source: any = {}) {
	        return new RPKIValidationROA(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.origin = source["origin"];
	        this.prefix = source["prefix"];
	        this.maxLength = source["maxLength"];
	        this.validity = source["validity"];
	    }
	}
	export class RPKIValidationDetailed {
	    asn: number;
	    prefix: string;
	    state: string;
	    roas?: RPKIValidationROA[];
	    evidence: ComponentEvidence;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new RPKIValidationDetailed(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.asn = source["asn"];
	        this.prefix = source["prefix"];
	        this.state = source["state"];
	        this.roas = this.convertValues(source["roas"], RPKIValidationROA);
	        this.evidence = this.convertValues(source["evidence"], ComponentEvidence);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class RPKISummary {
	    states?: Record<string, number>;
	    results?: RPKIValidationDetailed[];
	
	    static createFrom(source: any = {}) {
	        return new RPKISummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.states = source["states"];
	        this.results = this.convertValues(source["results"], RPKIValidationDetailed);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SeenEvent {
	    time: string;
	    origin: number;
	    prefix: string;
	
	    static createFrom(source: any = {}) {
	        return new SeenEvent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.time = source["time"];
	        this.origin = source["origin"];
	        this.prefix = source["prefix"];
	    }
	}
	export class Visibility {
	    family: string;
	    risPeersSeeing: number;
	    totalRisPeers: number;
	    ratio: number;
	    classification: string;
	
	    static createFrom(source: any = {}) {
	        return new Visibility(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.family = source["family"];
	        this.risPeersSeeing = source["risPeersSeeing"];
	        this.totalRisPeers = source["totalRisPeers"];
	        this.ratio = source["ratio"];
	        this.classification = source["classification"];
	    }
	}
	export class Overview {
	    resource: string;
	    kind: string;
	    asn?: number;
	    holder?: string;
	    prefixes?: string[];
	    announcedSpaceV4?: AnnouncedSpaceV4;
	    announcedSpaceV6?: AnnouncedSpaceV6;
	    visibilityV4?: Visibility;
	    visibilityV6?: Visibility;
	    firstSeen?: SeenEvent;
	    lastSeen?: SeenEvent;
	    origins?: number[];
	    moas: boolean;
	    rpki: RPKISummary;
	    neighbors: NeighborsSummary;
	    evidence: ComponentEvidence[];
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new Overview(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.resource = source["resource"];
	        this.kind = source["kind"];
	        this.asn = source["asn"];
	        this.holder = source["holder"];
	        this.prefixes = source["prefixes"];
	        this.announcedSpaceV4 = this.convertValues(source["announcedSpaceV4"], AnnouncedSpaceV4);
	        this.announcedSpaceV6 = this.convertValues(source["announcedSpaceV6"], AnnouncedSpaceV6);
	        this.visibilityV4 = this.convertValues(source["visibilityV4"], Visibility);
	        this.visibilityV6 = this.convertValues(source["visibilityV6"], Visibility);
	        this.firstSeen = this.convertValues(source["firstSeen"], SeenEvent);
	        this.lastSeen = this.convertValues(source["lastSeen"], SeenEvent);
	        this.origins = source["origins"];
	        this.moas = source["moas"];
	        this.rpki = this.convertValues(source["rpki"], RPKISummary);
	        this.neighbors = this.convertValues(source["neighbors"], NeighborsSummary);
	        this.evidence = this.convertValues(source["evidence"], ComponentEvidence);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PrefixTimeline {
	    startTime: string;
	    endTime: string;
	
	    static createFrom(source: any = {}) {
	        return new PrefixTimeline(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.startTime = source["startTime"];
	        this.endTime = source["endTime"];
	    }
	}
	export class PrefixRow {
	    prefix: string;
	    family: string;
	    timelines?: PrefixTimeline[];
	    visibility?: Visibility;
	    origins?: number[];
	    moas: boolean;
	    rpki?: RPKIValidationDetailed;
	    state: string;
	    evidence?: ComponentEvidence[];
	
	    static createFrom(source: any = {}) {
	        return new PrefixRow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.prefix = source["prefix"];
	        this.family = source["family"];
	        this.timelines = this.convertValues(source["timelines"], PrefixTimeline);
	        this.visibility = this.convertValues(source["visibility"], Visibility);
	        this.origins = source["origins"];
	        this.moas = source["moas"];
	        this.rpki = this.convertValues(source["rpki"], RPKIValidationDetailed);
	        this.state = source["state"];
	        this.evidence = this.convertValues(source["evidence"], ComponentEvidence);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PrefixPage {
	    ASN: number;
	    Page: number;
	    PageSize: number;
	    TotalItems: number;
	    TotalPages: number;
	    Items: PrefixRow[];
	    Evidence: ComponentEvidence[];
	    Err: string;
	
	    static createFrom(source: any = {}) {
	        return new PrefixPage(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ASN = source["ASN"];
	        this.Page = source["Page"];
	        this.PageSize = source["PageSize"];
	        this.TotalItems = source["TotalItems"];
	        this.TotalPages = source["TotalPages"];
	        this.Items = this.convertValues(source["Items"], PrefixRow);
	        this.Evidence = this.convertValues(source["Evidence"], ComponentEvidence);
	        this.Err = source["Err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PrefixPageRequest {
	    ASN: number;
	    Page: number;
	    Family: string;
	    Search: string;
	    Sort: string;
	
	    static createFrom(source: any = {}) {
	        return new PrefixPageRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ASN = source["ASN"];
	        this.Page = source["Page"];
	        this.Family = source["Family"];
	        this.Search = source["Search"];
	        this.Sort = source["Sort"];
	    }
	}
	
	
	
	export class RPKIObservatoryPoint {
	    time: string;
	    vrpCount?: number;
	    min?: number;
	    max?: number;
	    avg?: number;
	    first?: number;
	    last?: number;
	    samples?: number;
	
	    static createFrom(source: any = {}) {
	        return new RPKIObservatoryPoint(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.time = source["time"];
	        this.vrpCount = source["vrpCount"];
	        this.min = source["min"];
	        this.max = source["max"];
	        this.avg = source["avg"];
	        this.first = source["first"];
	        this.last = source["last"];
	        this.samples = source["samples"];
	    }
	}
	export class RPKIObservatoryRequest {
	    Resource: string;
	    Family: number;
	    Resolution: string;
	
	    static createFrom(source: any = {}) {
	        return new RPKIObservatoryRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Resource = source["Resource"];
	        this.Family = source["Family"];
	        this.Resolution = source["Resolution"];
	    }
	}
	export class RPKIObservatoryResult {
	    resource: string;
	    resourceKind: string;
	    family: number;
	    resolution: string;
	    points: RPKIObservatoryPoint[];
	    dataSufficient: boolean;
	    evidence: ComponentEvidence[];
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new RPKIObservatoryResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.resource = source["resource"];
	        this.resourceKind = source["resourceKind"];
	        this.family = source["family"];
	        this.resolution = source["resolution"];
	        this.points = this.convertValues(source["points"], RPKIObservatoryPoint);
	        this.dataSufficient = source["dataSufficient"];
	        this.evidence = this.convertValues(source["evidence"], ComponentEvidence);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class RPKIStatus {
	    asn: number;
	    prefix: string;
	    status?: string;
	    reason?: string;
	    disclosure: external.Disclosure;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new RPKIStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.asn = source["asn"];
	        this.prefix = source["prefix"];
	        this.status = source["status"];
	        this.reason = source["reason"];
	        this.disclosure = this.convertValues(source["disclosure"], external.Disclosure);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	export class RealtimeSessionInfo {
	    SessionID: string;
	    Resource: string;
	    ResourceKind: string;
	    ResolvedPrefix: string;
	    StartedAt: string;
	    State: string;
	    LastEventAt: string;
	    ReceivedEvents: number;
	    QueueDroppedEvents: number;
	    TransportDroppedEvents: number;
	    DroppedEventsTotal: number;
	    ReconnectCount: number;
	    LastError: string;
	    Disclosure: external.Disclosure;
	    DerivedStateEvictions: number;
	
	    static createFrom(source: any = {}) {
	        return new RealtimeSessionInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.SessionID = source["SessionID"];
	        this.Resource = source["Resource"];
	        this.ResourceKind = source["ResourceKind"];
	        this.ResolvedPrefix = source["ResolvedPrefix"];
	        this.StartedAt = source["StartedAt"];
	        this.State = source["State"];
	        this.LastEventAt = source["LastEventAt"];
	        this.ReceivedEvents = source["ReceivedEvents"];
	        this.QueueDroppedEvents = source["QueueDroppedEvents"];
	        this.TransportDroppedEvents = source["TransportDroppedEvents"];
	        this.DroppedEventsTotal = source["DroppedEventsTotal"];
	        this.ReconnectCount = source["ReconnectCount"];
	        this.LastError = source["LastError"];
	        this.Disclosure = this.convertValues(source["Disclosure"], external.Disclosure);
	        this.DerivedStateEvictions = source["DerivedStateEvictions"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class RouteStatus {
	    resource: string;
	    announced: boolean;
	    prefix?: string;
	    origins?: number[];
	    disclosure: external.Disclosure;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new RouteStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.resource = source["resource"];
	        this.announced = source["announced"];
	        this.prefix = source["prefix"];
	        this.origins = source["origins"];
	        this.disclosure = this.convertValues(source["disclosure"], external.Disclosure);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SecurityResult {
	    resource: string;
	    kind: string;
	    asn?: number;
	    prefix?: string;
	    origins?: number[];
	    moas: boolean;
	    rpki: RPKISummary;
	    health: HealthResult;
	    evidence: ComponentEvidence[];
	    complete: boolean;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new SecurityResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.resource = source["resource"];
	        this.kind = source["kind"];
	        this.asn = source["asn"];
	        this.prefix = source["prefix"];
	        this.origins = source["origins"];
	        this.moas = source["moas"];
	        this.rpki = this.convertValues(source["rpki"], RPKISummary);
	        this.health = this.convertValues(source["health"], HealthResult);
	        this.evidence = this.convertValues(source["evidence"], ComponentEvidence);
	        this.complete = source["complete"];
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	

}

export namespace capture {
	
	export class Device {
	    name: string;
	    description: string;
	
	    static createFrom(source: any = {}) {
	        return new Device(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	    }
	}

}

export namespace correlation {
	
	export class PcapFinding {
	    id: string;
	    category: string;
	    summary: string;
	    level: string;
	    confidence: number;
	    evidence?: model.Evidence[];
	    limitations?: string[];
	    sourceArea: string;
	
	    static createFrom(source: any = {}) {
	        return new PcapFinding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.category = source["category"];
	        this.summary = source["summary"];
	        this.level = source["level"];
	        this.confidence = source["confidence"];
	        this.evidence = this.convertValues(source["evidence"], model.Evidence);
	        this.limitations = source["limitations"];
	        this.sourceArea = source["sourceArea"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PcapSummaryStats {
	    packets: number;
	    flows: number;
	    endpoints: number;
	    publicEndpoints: number;
	    privateEndpoints: number;
	    otherEndpoints: number;
	    geoAvailable: boolean;
	    sipDetected: boolean;
	    topTalker?: string;
	    topASN?: string;
	    tcpResets: number;
	
	    static createFrom(source: any = {}) {
	        return new PcapSummaryStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.packets = source["packets"];
	        this.flows = source["flows"];
	        this.endpoints = source["endpoints"];
	        this.publicEndpoints = source["publicEndpoints"];
	        this.privateEndpoints = source["privateEndpoints"];
	        this.otherEndpoints = source["otherEndpoints"];
	        this.geoAvailable = source["geoAvailable"];
	        this.sipDetected = source["sipDetected"];
	        this.topTalker = source["topTalker"];
	        this.topASN = source["topASN"];
	        this.tcpResets = source["tcpResets"];
	    }
	}
	export class PcapIncidentSummary {
	    summary: string;
	    level: string;
	    confidence: number;
	    findings: PcapFinding[];
	    evidence?: model.Evidence[];
	    limitations?: string[];
	    stats: PcapSummaryStats;
	
	    static createFrom(source: any = {}) {
	        return new PcapIncidentSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.summary = source["summary"];
	        this.level = source["level"];
	        this.confidence = source["confidence"];
	        this.findings = this.convertValues(source["findings"], PcapFinding);
	        this.evidence = this.convertValues(source["evidence"], model.Evidence);
	        this.limitations = source["limitations"];
	        this.stats = this.convertValues(source["stats"], PcapSummaryStats);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class Snapshot {
	    schemaVersion: number;
	    kind: string;
	    sourceId?: string;
	    subject?: string;
	    occurredAt?: string;
	    assessment: model.Assessment;
	
	    static createFrom(source: any = {}) {
	        return new Snapshot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schemaVersion = source["schemaVersion"];
	        this.kind = source["kind"];
	        this.sourceId = source["sourceId"];
	        this.subject = source["subject"];
	        this.occurredAt = source["occurredAt"];
	        this.assessment = this.convertValues(source["assessment"], model.Assessment);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace dnsintel {
	
	export class DNSSECInfo {
	    requested: boolean;
	    authenticated: boolean;
	    hasRRSIG: boolean;
	
	    static createFrom(source: any = {}) {
	        return new DNSSECInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.requested = source["requested"];
	        this.authenticated = source["authenticated"];
	        this.hasRRSIG = source["hasRRSIG"];
	    }
	}
	export class SRVData {
	    priority: number;
	    weight: number;
	    port: number;
	    target: string;
	
	    static createFrom(source: any = {}) {
	        return new SRVData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.priority = source["priority"];
	        this.weight = source["weight"];
	        this.port = source["port"];
	        this.target = source["target"];
	    }
	}
	export class Record {
	    name: string;
	    type: string;
	    ttl: number;
	    value: string;
	    srv?: SRVData;
	
	    static createFrom(source: any = {}) {
	        return new Record(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.type = source["type"];
	        this.ttl = source["ttl"];
	        this.value = source["value"];
	        this.srv = this.convertValues(source["srv"], SRVData);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class QueryResult {
	    domain: string;
	    type: string;
	    resolver: string;
	    records: Record[];
	    rcode: string;
	    truncated: boolean;
	    durationMs: number;
	    dnssec: DNSSECInfo;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new QueryResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.domain = source["domain"];
	        this.type = source["type"];
	        this.resolver = source["resolver"];
	        this.records = this.convertValues(source["records"], Record);
	        this.rcode = source["rcode"];
	        this.truncated = source["truncated"];
	        this.durationMs = source["durationMs"];
	        this.dnssec = this.convertValues(source["dnssec"], DNSSECInfo);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Comparison {
	    domain: string;
	    type: string;
	    results: QueryResult[];
	    consistent: boolean;
	    divergences?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Comparison(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.domain = source["domain"];
	        this.type = source["type"];
	        this.results = this.convertValues(source["results"], QueryResult);
	        this.consistent = source["consistent"];
	        this.divergences = source["divergences"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	export class Resolver {
	    addr: string;
	    label: string;
	
	    static createFrom(source: any = {}) {
	        return new Resolver(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.addr = source["addr"];
	        this.label = source["label"];
	    }
	}
	
	export class SRVDiscoveryCandidate {
	    name: string;
	    result: QueryResult;
	
	    static createFrom(source: any = {}) {
	        return new SRVDiscoveryCandidate(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.result = this.convertValues(source["result"], QueryResult);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TargetResolution {
	    target: string;
	    ips: string[];
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new TargetResolution(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = source["target"];
	        this.ips = source["ips"];
	        this.err = source["err"];
	    }
	}

}

export namespace external {
	
	export class Disclosure {
	    source: string;
	    queriedAt: string;
	    dataSent: string;
	    cachePolicy: string;
	    confidence: string;
	    rateLimit: string;
	
	    static createFrom(source: any = {}) {
	        return new Disclosure(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.source = source["source"];
	        this.queriedAt = source["queriedAt"];
	        this.dataSent = source["dataSent"];
	        this.cachePolicy = source["cachePolicy"];
	        this.confidence = source["confidence"];
	        this.rateLimit = source["rateLimit"];
	    }
	}

}

export namespace flow {
	
	export class Flow {
	    proto: string;
	    aAddr: string;
	    aPort?: number;
	    bAddr: string;
	    bPort?: number;
	    pktsAB: number;
	    pktsBA: number;
	    bytesAB: number;
	    bytesBA: number;
	    packets: number;
	    bytes: number;
	    start?: string;
	    end?: string;
	    durationSec: number;
	    apps?: string[];
	    resets?: number;
	
	    static createFrom(source: any = {}) {
	        return new Flow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.proto = source["proto"];
	        this.aAddr = source["aAddr"];
	        this.aPort = source["aPort"];
	        this.bAddr = source["bAddr"];
	        this.bPort = source["bPort"];
	        this.pktsAB = source["pktsAB"];
	        this.pktsBA = source["pktsBA"];
	        this.bytesAB = source["bytesAB"];
	        this.bytesBA = source["bytesBA"];
	        this.packets = source["packets"];
	        this.bytes = source["bytes"];
	        this.start = source["start"];
	        this.end = source["end"];
	        this.durationSec = source["durationSec"];
	        this.apps = source["apps"];
	        this.resets = source["resets"];
	    }
	}

}

export namespace geoip {
	
	export class DatasetInfo {
	    name: string;
	    path: string;
	    type?: string;
	    buildEpoch?: number;
	    present: boolean;
	
	    static createFrom(source: any = {}) {
	        return new DatasetInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.path = source["path"];
	        this.type = source["type"];
	        this.buildEpoch = source["buildEpoch"];
	        this.present = source["present"];
	    }
	}
	export class Result {
	    country?: string;
	    countryCode?: string;
	    region?: string;
	    city?: string;
	    lat?: number;
	    lon?: number;
	    asn?: number;
	    org?: string;
	    hasGeo: boolean;
	    hasASN: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.country = source["country"];
	        this.countryCode = source["countryCode"];
	        this.region = source["region"];
	        this.city = source["city"];
	        this.lat = source["lat"];
	        this.lon = source["lon"];
	        this.asn = source["asn"];
	        this.org = source["org"];
	        this.hasGeo = source["hasGeo"];
	        this.hasASN = source["hasASN"];
	    }
	}

}

export namespace geoupdate {
	
	export class Result {
	    checkedAt: string;
	    updated: string[];
	    current: string[];
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.checkedAt = source["checkedAt"];
	        this.updated = source["updated"];
	        this.current = source["current"];
	    }
	}
	export class Status {
	    accountId: string;
	    hasLicenseKey: boolean;
	    autoUpdate: boolean;
	    busy: boolean;
	    lastCheck?: string;
	    lastSuccess?: string;
	    lastError?: string;
	    dataDir: string;
	    datasets: geoip.DatasetInfo[];
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.accountId = source["accountId"];
	        this.hasLicenseKey = source["hasLicenseKey"];
	        this.autoUpdate = source["autoUpdate"];
	        this.busy = source["busy"];
	        this.lastCheck = source["lastCheck"];
	        this.lastSuccess = source["lastSuccess"];
	        this.lastError = source["lastError"];
	        this.dataDir = source["dataDir"];
	        this.datasets = this.convertValues(source["datasets"], geoip.DatasetInfo);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace httpintel {
	
	export class Timing {
	    dnsMs: number;
	    connectMs: number;
	    tlsMs: number;
	    ttfbMs: number;
	    totalMs: number;
	
	    static createFrom(source: any = {}) {
	        return new Timing(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.dnsMs = source["dnsMs"];
	        this.connectMs = source["connectMs"];
	        this.tlsMs = source["tlsMs"];
	        this.ttfbMs = source["ttfbMs"];
	        this.totalMs = source["totalMs"];
	    }
	}
	export class Hop {
	    url: string;
	    method: string;
	    statusCode: number;
	    location?: string;
	    headers: Record<string, Array<string>>;
	    timing: Timing;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new Hop(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.url = source["url"];
	        this.method = source["method"];
	        this.statusCode = source["statusCode"];
	        this.location = source["location"];
	        this.headers = source["headers"];
	        this.timing = this.convertValues(source["timing"], Timing);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Signal {
	    label: string;
	    evidence: string;
	
	    static createFrom(source: any = {}) {
	        return new Signal(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.evidence = source["evidence"];
	    }
	}
	export class SecurityHeader {
	    name: string;
	    present: boolean;
	    value?: string;
	
	    static createFrom(source: any = {}) {
	        return new SecurityHeader(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.present = source["present"];
	        this.value = source["value"];
	    }
	}
	export class Result {
	    requestedURL: string;
	    finalURL: string;
	    method: string;
	    redirects: Hop[];
	    finalStatus: number;
	    headers: Record<string, Array<string>>;
	    securityHeaders: SecurityHeader[];
	    signals: Signal[];
	    bodyBytesRead: number;
	    bodyTruncated: boolean;
	    durationMs: number;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.requestedURL = source["requestedURL"];
	        this.finalURL = source["finalURL"];
	        this.method = source["method"];
	        this.redirects = this.convertValues(source["redirects"], Hop);
	        this.finalStatus = source["finalStatus"];
	        this.headers = source["headers"];
	        this.securityHeaders = this.convertValues(source["securityHeaders"], SecurityHeader);
	        this.signals = this.convertValues(source["signals"], Signal);
	        this.bodyBytesRead = source["bodyBytesRead"];
	        this.bodyTruncated = source["bodyTruncated"];
	        this.durationMs = source["durationMs"];
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	

}

export namespace investigation {
	
	export class Entry {
	    id: string;
	    addedAt: string;
	    snapshot: correlation.Snapshot;
	    note?: string;
	    fingerprint: string;
	
	    static createFrom(source: any = {}) {
	        return new Entry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.addedAt = source["addedAt"];
	        this.snapshot = this.convertValues(source["snapshot"], correlation.Snapshot);
	        this.note = source["note"];
	        this.fingerprint = source["fingerprint"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Investigation {
	    schemaVersion: number;
	    id: string;
	    name: string;
	    objective?: string;
	    createdAt: string;
	    updatedAt: string;
	    entries: Entry[];
	
	    static createFrom(source: any = {}) {
	        return new Investigation(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schemaVersion = source["schemaVersion"];
	        this.id = source["id"];
	        this.name = source["name"];
	        this.objective = source["objective"];
	        this.createdAt = source["createdAt"];
	        this.updatedAt = source["updatedAt"];
	        this.entries = this.convertValues(source["entries"], Entry);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Summary {
	    id: string;
	    name: string;
	    objective?: string;
	    createdAt: string;
	    updatedAt: string;
	    entryCount: number;
	    highestLevel: string;
	    sourceCounts?: Record<string, number>;
	    mainFinding?: string;
	
	    static createFrom(source: any = {}) {
	        return new Summary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.objective = source["objective"];
	        this.createdAt = source["createdAt"];
	        this.updatedAt = source["updatedAt"];
	        this.entryCount = source["entryCount"];
	        this.highestLevel = source["highestLevel"];
	        this.sourceCounts = source["sourceCounts"];
	        this.mainFinding = source["mainFinding"];
	    }
	}
	export class ListResult {
	    investigations: Summary[];
	    warnings?: string[];
	
	    static createFrom(source: any = {}) {
	        return new ListResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.investigations = this.convertValues(source["investigations"], Summary);
	        this.warnings = source["warnings"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace ipcalc {
	
	export class CustomerPlan {
	    requested: number;
	    reserveGateway: boolean;
	    prefixLen: number;
	    block: string;
	    total: number;
	    usableInSubnet: number;
	    networkReserved: number;
	    broadcastReserved: number;
	    gatewayReserved: number;
	    spare: number;
	    notAssignedToCustomer: number;
	
	    static createFrom(source: any = {}) {
	        return new CustomerPlan(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.requested = source["requested"];
	        this.reserveGateway = source["reserveGateway"];
	        this.prefixLen = source["prefixLen"];
	        this.block = source["block"];
	        this.total = source["total"];
	        this.usableInSubnet = source["usableInSubnet"];
	        this.networkReserved = source["networkReserved"];
	        this.broadcastReserved = source["broadcastReserved"];
	        this.gatewayReserved = source["gatewayReserved"];
	        this.spare = source["spare"];
	        this.notAssignedToCustomer = source["notAssignedToCustomer"];
	    }
	}
	export class Info {
	    input: string;
	    family: string;
	    addr: string;
	    prefix: string;
	    prefixLen: number;
	    network: string;
	    broadcast?: string;
	    firstHost: string;
	    lastHost: string;
	    totalCount: string;
	    usableCount: string;
	    netmask?: string;
	    wildcard?: string;
	    addrBinary: string;
	    networkBinary: string;
	    maskBinary?: string;
	    class?: string;
	    classes: string[];
	    isPublic: boolean;
	    decimal?: string;
	    hex: string;
	    expanded?: string;
	    compressed?: string;
	    ptr: string;
	    reverseZone: string;
	    notes?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Info(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.input = source["input"];
	        this.family = source["family"];
	        this.addr = source["addr"];
	        this.prefix = source["prefix"];
	        this.prefixLen = source["prefixLen"];
	        this.network = source["network"];
	        this.broadcast = source["broadcast"];
	        this.firstHost = source["firstHost"];
	        this.lastHost = source["lastHost"];
	        this.totalCount = source["totalCount"];
	        this.usableCount = source["usableCount"];
	        this.netmask = source["netmask"];
	        this.wildcard = source["wildcard"];
	        this.addrBinary = source["addrBinary"];
	        this.networkBinary = source["networkBinary"];
	        this.maskBinary = source["maskBinary"];
	        this.class = source["class"];
	        this.classes = source["classes"];
	        this.isPublic = source["isPublic"];
	        this.decimal = source["decimal"];
	        this.hex = source["hex"];
	        this.expanded = source["expanded"];
	        this.compressed = source["compressed"];
	        this.ptr = source["ptr"];
	        this.reverseZone = source["reverseZone"];
	        this.notes = source["notes"];
	    }
	}
	export class Subnet {
	    index: number;
	    prefix: string;
	    network: string;
	    broadcast?: string;
	    firstHost: string;
	    lastHost: string;
	    usableCount: string;
	
	    static createFrom(source: any = {}) {
	        return new Subnet(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.index = source["index"];
	        this.prefix = source["prefix"];
	        this.network = source["network"];
	        this.broadcast = source["broadcast"];
	        this.firstHost = source["firstHost"];
	        this.lastHost = source["lastHost"];
	        this.usableCount = source["usableCount"];
	    }
	}
	export class SplitResult {
	    rows: Subnet[];
	    total: string;
	    truncated: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SplitResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.rows = this.convertValues(source["rows"], Subnet);
	        this.total = source["total"];
	        this.truncated = source["truncated"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class VLSMAlloc {
	    label: string;
	    hostsAsked: number;
	    prefixLen: number;
	    prefix: string;
	    network: string;
	    broadcast?: string;
	    firstHost: string;
	    lastHost: string;
	    usableCount: number;
	    waste: number;
	    note?: string;
	
	    static createFrom(source: any = {}) {
	        return new VLSMAlloc(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.hostsAsked = source["hostsAsked"];
	        this.prefixLen = source["prefixLen"];
	        this.prefix = source["prefix"];
	        this.network = source["network"];
	        this.broadcast = source["broadcast"];
	        this.firstHost = source["firstHost"];
	        this.lastHost = source["lastHost"];
	        this.usableCount = source["usableCount"];
	        this.waste = source["waste"];
	        this.note = source["note"];
	    }
	}
	export class VLSMRequest {
	    label: string;
	    hosts: number;
	
	    static createFrom(source: any = {}) {
	        return new VLSMRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.hosts = source["hosts"];
	    }
	}
	export class VLSMResult {
	    allocations: VLSMAlloc[];
	    remaining: string[];
	    usedPct: number;
	
	    static createFrom(source: any = {}) {
	        return new VLSMResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.allocations = this.convertValues(source["allocations"], VLSMAlloc);
	        this.remaining = source["remaining"];
	        this.usedPct = source["usedPct"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace lab {
	
	export class Fact {
	    key: string;
	    label: string;
	    value: string;
	
	    static createFrom(source: any = {}) {
	        return new Fact(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.label = source["label"];
	        this.value = source["value"];
	    }
	}
	export class Objective {
	    question: string;
	    hint?: string;
	
	    static createFrom(source: any = {}) {
	        return new Objective(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.question = source["question"];
	        this.hint = source["hint"];
	    }
	}
	export class RunResult {
	    scenarioId: string;
	    pcapPath: string;
	    ranAt: string;
	    expected: Fact[];
	    actual: Fact[];
	    matches: Record<string, boolean>;
	    allMatch: boolean;
	    passed: number;
	    total: number;
	    score: number;
	    status: string;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new RunResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.scenarioId = source["scenarioId"];
	        this.pcapPath = source["pcapPath"];
	        this.ranAt = source["ranAt"];
	        this.expected = this.convertValues(source["expected"], Fact);
	        this.actual = this.convertValues(source["actual"], Fact);
	        this.matches = source["matches"];
	        this.allMatch = source["allMatch"];
	        this.passed = source["passed"];
	        this.total = source["total"];
	        this.score = source["score"];
	        this.status = source["status"];
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Scenario {
	    id: string;
	    title: string;
	    description: string;
	    technique?: string;
	    signal?: string;
	    objectives: Objective[];
	    expected: Fact[];
	
	    static createFrom(source: any = {}) {
	        return new Scenario(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = source["title"];
	        this.description = source["description"];
	        this.technique = source["technique"];
	        this.signal = source["signal"];
	        this.objectives = this.convertValues(source["objectives"], Objective);
	        this.expected = this.convertValues(source["expected"], Fact);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace lan {
	
	export class HostResult {
	    ip: string;
	    up: boolean;
	    hostname?: string;
	    mac?: string;
	    vendor?: string;
	    rttMs?: number;
	    openPorts?: portscan.PortResult[];
	    osGuess?: string;
	    iface?: string;
	
	    static createFrom(source: any = {}) {
	        return new HostResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.up = source["up"];
	        this.hostname = source["hostname"];
	        this.mac = source["mac"];
	        this.vendor = source["vendor"];
	        this.rttMs = source["rttMs"];
	        this.openPorts = this.convertValues(source["openPorts"], portscan.PortResult);
	        this.osGuess = source["osGuess"];
	        this.iface = source["iface"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Neighbor {
	    ip: string;
	    mac: string;
	    vendor?: string;
	    type?: string;
	
	    static createFrom(source: any = {}) {
	        return new Neighbor(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	        this.vendor = source["vendor"];
	        this.type = source["type"];
	    }
	}
	export class NetworkInterface {
	    name: string;
	    mac?: string;
	    vendor?: string;
	    addrs: string[];
	    up: boolean;
	    loopback: boolean;
	    mtu: number;
	
	    static createFrom(source: any = {}) {
	        return new NetworkInterface(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.mac = source["mac"];
	        this.vendor = source["vendor"];
	        this.addrs = source["addrs"];
	        this.up = source["up"];
	        this.loopback = source["loopback"];
	        this.mtu = source["mtu"];
	    }
	}
	export class Report {
	    interfaces: NetworkInterface[];
	    neighbors: Neighbor[];
	    note?: string;
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.interfaces = this.convertValues(source["interfaces"], NetworkInterface);
	        this.neighbors = this.convertValues(source["neighbors"], Neighbor);
	        this.note = source["note"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TrustFinding {
	    level: string;
	    kind: string;
	    identity: string;
	    ip?: string;
	    mac?: string;
	    summary: string;
	    evidence?: string;
	
	    static createFrom(source: any = {}) {
	        return new TrustFinding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.level = source["level"];
	        this.kind = source["kind"];
	        this.identity = source["identity"];
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	        this.summary = source["summary"];
	        this.evidence = source["evidence"];
	    }
	}
	export class TrustResult {
	    baselineCreated: boolean;
	    knownDevices: number;
	    observedDevices: number;
	    findings: TrustFinding[];
	    updatedAt: string;
	
	    static createFrom(source: any = {}) {
	        return new TrustResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.baselineCreated = source["baselineCreated"];
	        this.knownDevices = source["knownDevices"];
	        this.observedDevices = source["observedDevices"];
	        this.findings = this.convertValues(source["findings"], TrustFinding);
	        this.updatedAt = source["updatedAt"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace model {
	
	export class Evidence {
	    type: string;
	    value: string;
	    source: string;
	    provenance: string;
	    // Go type: time
	    timestamp: any;
	    confidence: number;
	    explain?: string;
	
	    static createFrom(source: any = {}) {
	        return new Evidence(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.value = source["value"];
	        this.source = source["source"];
	        this.provenance = source["provenance"];
	        this.timestamp = this.convertValues(source["timestamp"], null);
	        this.confidence = source["confidence"];
	        this.explain = source["explain"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Assessment {
	    conclusion: string;
	    level: string;
	    confidence: number;
	    evidence?: Evidence[];
	    counterEvidence?: Evidence[];
	    limitations?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Assessment(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.conclusion = source["conclusion"];
	        this.level = source["level"];
	        this.confidence = source["confidence"];
	        this.evidence = this.convertValues(source["evidence"], Evidence);
	        this.counterEvidence = this.convertValues(source["counterEvidence"], Evidence);
	        this.limitations = source["limitations"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace monitor {
	
	export class WindowStats {
	    from: string;
	    to: string;
	    samples: number;
	    lossPct: number;
	    avgRttMs: number;
	    maxRttMs: number;
	    minRttMs: number;
	
	    static createFrom(source: any = {}) {
	        return new WindowStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.from = source["from"];
	        this.to = source["to"];
	        this.samples = source["samples"];
	        this.lossPct = source["lossPct"];
	        this.avgRttMs = source["avgRttMs"];
	        this.maxRttMs = source["maxRttMs"];
	        this.minRttMs = source["minRttMs"];
	    }
	}
	export class BaselineProfile {
	    pinnedAt: string;
	    windowFrom: string;
	    windowTo: string;
	    samples: number;
	    avgRttMs: number;
	    lossPct: number;
	
	    static createFrom(source: any = {}) {
	        return new BaselineProfile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pinnedAt = source["pinnedAt"];
	        this.windowFrom = source["windowFrom"];
	        this.windowTo = source["windowTo"];
	        this.samples = source["samples"];
	        this.avgRttMs = source["avgRttMs"];
	        this.lossPct = source["lossPct"];
	    }
	}
	export class BaselineComparison {
	    baseline: BaselineProfile;
	    current: WindowStats;
	    deltaAvgRttMs: number;
	    deltaLossPct: number;
	
	    static createFrom(source: any = {}) {
	        return new BaselineComparison(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.baseline = this.convertValues(source["baseline"], BaselineProfile);
	        this.current = this.convertValues(source["current"], WindowStats);
	        this.deltaAvgRttMs = source["deltaAvgRttMs"];
	        this.deltaLossPct = source["deltaLossPct"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class RouteHop {
	    ttl: number;
	    addr?: string;
	    host?: string;
	
	    static createFrom(source: any = {}) {
	        return new RouteHop(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ttl = source["ttl"];
	        this.addr = source["addr"];
	        this.host = source["host"];
	    }
	}
	export class RouteChange {
	    id: string;
	    targetId: string;
	    detectedAt: string;
	    firstChangedTtl: number;
	    before: RouteHop[];
	    after: RouteHop[];
	    beforeHopCount: number;
	    afterHopCount: number;
	    changeTypes: string[];
	    persistent: boolean;
	    confidence: number;
	    coincidentDegradation: boolean;
	    rttBefore?: number;
	    rttAfter?: number;
	    lossBefore?: number;
	    lossAfter?: number;
	    evidence?: model.Evidence[];
	    limitations?: string[];
	
	    static createFrom(source: any = {}) {
	        return new RouteChange(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.targetId = source["targetId"];
	        this.detectedAt = source["detectedAt"];
	        this.firstChangedTtl = source["firstChangedTtl"];
	        this.before = this.convertValues(source["before"], RouteHop);
	        this.after = this.convertValues(source["after"], RouteHop);
	        this.beforeHopCount = source["beforeHopCount"];
	        this.afterHopCount = source["afterHopCount"];
	        this.changeTypes = source["changeTypes"];
	        this.persistent = source["persistent"];
	        this.confidence = source["confidence"];
	        this.coincidentDegradation = source["coincidentDegradation"];
	        this.rttBefore = source["rttBefore"];
	        this.rttAfter = source["rttAfter"];
	        this.lossBefore = source["lossBefore"];
	        this.lossAfter = source["lossAfter"];
	        this.evidence = this.convertValues(source["evidence"], model.Evidence);
	        this.limitations = source["limitations"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class DegradationEvent {
	    time: string;
	    kind: string;
	    detail: string;
	    routeChange?: RouteChange;
	
	    static createFrom(source: any = {}) {
	        return new DegradationEvent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.time = source["time"];
	        this.kind = source["kind"];
	        this.detail = source["detail"];
	        this.routeChange = this.convertValues(source["routeChange"], RouteChange);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Hop {
	    ttl: number;
	    addr?: string;
	    host?: string;
	    lossPct: number;
	    avgMs: number;
	
	    static createFrom(source: any = {}) {
	        return new Hop(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ttl = source["ttl"];
	        this.addr = source["addr"];
	        this.host = source["host"];
	        this.lossPct = source["lossPct"];
	        this.avgMs = source["avgMs"];
	    }
	}
	export class Sample {
	    time: string;
	    ok: boolean;
	    rttMs: number;
	    lossPct: number;
	    hopCount?: number;
	    hops?: Hop[];
	
	    static createFrom(source: any = {}) {
	        return new Sample(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.time = source["time"];
	        this.ok = source["ok"];
	        this.rttMs = source["rttMs"];
	        this.lossPct = source["lossPct"];
	        this.hopCount = source["hopCount"];
	        this.hops = this.convertValues(source["hops"], Hop);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Target {
	    id: string;
	    label: string;
	    address: string;
	    mode: string;
	    intervalMs: number;
	    retentionHours: number;
	    createdAt: string;
	
	    static createFrom(source: any = {}) {
	        return new Target(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.label = source["label"];
	        this.address = source["address"];
	        this.mode = source["mode"];
	        this.intervalMs = source["intervalMs"];
	        this.retentionHours = source["retentionHours"];
	        this.createdAt = source["createdAt"];
	    }
	}
	export class History {
	    target: Target;
	    samples: Sample[];
	    events: DegradationEvent[];
	    baseline?: BaselineProfile;
	
	    static createFrom(source: any = {}) {
	        return new History(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = this.convertValues(source["target"], Target);
	        this.samples = this.convertValues(source["samples"], Sample);
	        this.events = this.convertValues(source["events"], DegradationEvent);
	        this.baseline = this.convertValues(source["baseline"], BaselineProfile);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	
	
	export class WindowComparison {
	    targetId: string;
	    recent: WindowStats;
	    previous: WindowStats;
	    deltaAvgRttMs: number;
	    deltaLossPct: number;
	
	    static createFrom(source: any = {}) {
	        return new WindowComparison(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.targetId = source["targetId"];
	        this.recent = this.convertValues(source["recent"], WindowStats);
	        this.previous = this.convertValues(source["previous"], WindowStats);
	        this.deltaAvgRttMs = source["deltaAvgRttMs"];
	        this.deltaLossPct = source["deltaLossPct"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace netclass {
	
	export class Match {
	    category: string;
	    provider?: string;
	    service?: string;
	    region?: string;
	    prefix?: string;
	    source: string;
	    confidence: string;
	    evidence: string;
	    inferred: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Match(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.category = source["category"];
	        this.provider = source["provider"];
	        this.service = source["service"];
	        this.region = source["region"];
	        this.prefix = source["prefix"];
	        this.source = source["source"];
	        this.confidence = source["confidence"];
	        this.evidence = source["evidence"];
	        this.inferred = source["inferred"];
	    }
	}
	export class SourceInfo {
	    id: string;
	    name: string;
	    url: string;
	    fetchedAt: string;
	    sha256: string;
	    prefixCount: number;
	    present: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SourceInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.url = source["url"];
	        this.fetchedAt = source["fetchedAt"];
	        this.sha256 = source["sha256"];
	        this.prefixCount = source["prefixCount"];
	        this.present = source["present"];
	    }
	}

}

export namespace netdiag {
	
	export class Finding {
	    id: string;
	    kind: string;
	    severity: string;
	    confidence: number;
	    subject: string;
	    count: number;
	    ratePerSec?: number;
	    evidence: string[];
	    summary: string;
	    explain: string;
	    caveat?: string;
	
	    static createFrom(source: any = {}) {
	        return new Finding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.kind = source["kind"];
	        this.severity = source["severity"];
	        this.confidence = source["confidence"];
	        this.subject = source["subject"];
	        this.count = source["count"];
	        this.ratePerSec = source["ratePerSec"];
	        this.evidence = source["evidence"];
	        this.summary = source["summary"];
	        this.explain = source["explain"];
	        this.caveat = source["caveat"];
	    }
	}
	export class Neighbor {
	    mac: string;
	    ip?: string;
	    protocol: string;
	    vendor?: string;
	    count: number;
	
	    static createFrom(source: any = {}) {
	        return new Neighbor(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mac = source["mac"];
	        this.ip = source["ip"];
	        this.protocol = source["protocol"];
	        this.vendor = source["vendor"];
	        this.count = source["count"];
	    }
	}
	export class Result {
	    frames: number;
	    broadcasts: number;
	    loopedFrames: number;
	    findings: Finding[];
	    neighbors: Neighbor[];
	    truncated: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.frames = source["frames"];
	        this.broadcasts = source["broadcasts"];
	        this.loopedFrames = source["loopedFrames"];
	        this.findings = this.convertValues(source["findings"], Finding);
	        this.neighbors = this.convertValues(source["neighbors"], Neighbor);
	        this.truncated = source["truncated"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace oui {
	
	export class Detail {
	    input: string;
	    mac?: string;
	    valid: boolean;
	    vendor?: string;
	    prefix?: string;
	    registry?: string;
	    local: boolean;
	    multicast: boolean;
	    broadcast: boolean;
	    note?: string;
	
	    static createFrom(source: any = {}) {
	        return new Detail(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.input = source["input"];
	        this.mac = source["mac"];
	        this.valid = source["valid"];
	        this.vendor = source["vendor"];
	        this.prefix = source["prefix"];
	        this.registry = source["registry"];
	        this.local = source["local"];
	        this.multicast = source["multicast"];
	        this.broadcast = source["broadcast"];
	        this.note = source["note"];
	    }
	}
	export class Info {
	    present: boolean;
	    fetchedAt?: string;
	    prefixCount: number;
	    registries?: string;
	    source: string;
	
	    static createFrom(source: any = {}) {
	        return new Info(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.present = source["present"];
	        this.fetchedAt = source["fetchedAt"];
	        this.prefixCount = source["prefixCount"];
	        this.registries = source["registries"];
	        this.source = source["source"];
	    }
	}

}

export namespace packet {
	
	export class Summary {
	    index: number;
	    time: string;
	    timeUnix: number;
	    length: number;
	    src: string;
	    dst: string;
	    srcMAC?: string;
	    dstMAC?: string;
	    etherType?: string;
	    ipID?: number;
	    srcPort?: number;
	    dstPort?: number;
	    proto: string;
	    transport?: string;
	    ttl?: number;
	    tcpFlags?: string[];
	    payloadLen?: number;
	    payloadHex?: string;
	    info: string;
	    app?: string;
	    layers: string[];
	    err?: string;
	    ssid?: string;
	    bssid?: string;
	    channel?: number;
	    wifiType?: string;
	
	    static createFrom(source: any = {}) {
	        return new Summary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.index = source["index"];
	        this.time = source["time"];
	        this.timeUnix = source["timeUnix"];
	        this.length = source["length"];
	        this.src = source["src"];
	        this.dst = source["dst"];
	        this.srcMAC = source["srcMAC"];
	        this.dstMAC = source["dstMAC"];
	        this.etherType = source["etherType"];
	        this.ipID = source["ipID"];
	        this.srcPort = source["srcPort"];
	        this.dstPort = source["dstPort"];
	        this.proto = source["proto"];
	        this.transport = source["transport"];
	        this.ttl = source["ttl"];
	        this.tcpFlags = source["tcpFlags"];
	        this.payloadLen = source["payloadLen"];
	        this.payloadHex = source["payloadHex"];
	        this.info = source["info"];
	        this.app = source["app"];
	        this.layers = source["layers"];
	        this.err = source["err"];
	        this.ssid = source["ssid"];
	        this.bssid = source["bssid"];
	        this.channel = source["channel"];
	        this.wifiType = source["wifiType"];
	    }
	}

}

export namespace pcap {
	
	export class Info {
	    format: string;
	    linkType: string;
	    packets: number;
	    bytes: number;
	    firstTime?: string;
	    lastTime?: string;
	    durationSec: number;
	    truncated: boolean;
	    linkTypeNum: number;
	    undecodable: number;
	    tzspDecapsulated: number;
	    gpsFixes: number;
	    firstFix?: ppi.Fix;
	    lastFix?: ppi.Fix;
	
	    static createFrom(source: any = {}) {
	        return new Info(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.format = source["format"];
	        this.linkType = source["linkType"];
	        this.packets = source["packets"];
	        this.bytes = source["bytes"];
	        this.firstTime = source["firstTime"];
	        this.lastTime = source["lastTime"];
	        this.durationSec = source["durationSec"];
	        this.truncated = source["truncated"];
	        this.linkTypeNum = source["linkTypeNum"];
	        this.undecodable = source["undecodable"];
	        this.tzspDecapsulated = source["tzspDecapsulated"];
	        this.gpsFixes = source["gpsFixes"];
	        this.firstFix = this.convertValues(source["firstFix"], ppi.Fix);
	        this.lastFix = this.convertValues(source["lastFix"], ppi.Fix);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace phoneintel {
	
	export class Result {
	    input: string;
	    valid: boolean;
	    e164?: string;
	    international?: string;
	    national?: string;
	    rfc3966?: string;
	    countryCode?: number;
	    region?: string;
	    area?: string;
	    kind: string;
	    kindNote?: string;
	    carrier?: string;
	    carrierNote?: string;
	    timezones: string[];
	    notes: string[];
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.input = source["input"];
	        this.valid = source["valid"];
	        this.e164 = source["e164"];
	        this.international = source["international"];
	        this.national = source["national"];
	        this.rfc3966 = source["rfc3966"];
	        this.countryCode = source["countryCode"];
	        this.region = source["region"];
	        this.area = source["area"];
	        this.kind = source["kind"];
	        this.kindNote = source["kindNote"];
	        this.carrier = source["carrier"];
	        this.carrierNote = source["carrierNote"];
	        this.timezones = source["timezones"];
	        this.notes = source["notes"];
	        this.err = source["err"];
	    }
	}

}

export namespace portscan {
	
	export class PortResult {
	    port: number;
	    state: string;
	    service?: string;
	    rttMs?: number;
	
	    static createFrom(source: any = {}) {
	        return new PortResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.port = source["port"];
	        this.state = source["state"];
	        this.service = source["service"];
	        this.rttMs = source["rttMs"];
	    }
	}

}

export namespace ppi {
	
	export class Fix {
	    latitude?: number;
	    longitude?: number;
	    altitudeM?: number;
	
	    static createFrom(source: any = {}) {
	        return new Fix(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.latitude = source["latitude"];
	        this.longitude = source["longitude"];
	        this.altitudeM = source["altitudeM"];
	    }
	}

}

export namespace quality {
	
	export class Sample {
	    time: string;
	    callId: string;
	    from?: string;
	    to?: string;
	    established: boolean;
	    avgJitterMs: number;
	    avgLossPct: number;
	    mos?: number;
	
	    static createFrom(source: any = {}) {
	        return new Sample(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.time = source["time"];
	        this.callId = source["callId"];
	        this.from = source["from"];
	        this.to = source["to"];
	        this.established = source["established"];
	        this.avgJitterMs = source["avgJitterMs"];
	        this.avgLossPct = source["avgLossPct"];
	        this.mos = source["mos"];
	    }
	}
	export class Target {
	    id: string;
	    label: string;
	    match: string;
	    createdAt: string;
	
	    static createFrom(source: any = {}) {
	        return new Target(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.label = source["label"];
	        this.match = source["match"];
	        this.createdAt = source["createdAt"];
	    }
	}
	export class History {
	    target: Target;
	    samples: Sample[];
	
	    static createFrom(source: any = {}) {
	        return new History(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = this.convertValues(source["target"], Target);
	        this.samples = this.convertValues(source["samples"], Sample);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	export class WindowStats {
	    from: string;
	    to: string;
	    samples: number;
	    avgJitterMs: number;
	    avgLossPct: number;
	    avgMos: number;
	
	    static createFrom(source: any = {}) {
	        return new WindowStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.from = source["from"];
	        this.to = source["to"];
	        this.samples = source["samples"];
	        this.avgJitterMs = source["avgJitterMs"];
	        this.avgLossPct = source["avgLossPct"];
	        this.avgMos = source["avgMos"];
	    }
	}
	export class WindowComparison {
	    targetId: string;
	    recent: WindowStats;
	    previous: WindowStats;
	    deltaJitterMs: number;
	    deltaLossPct: number;
	    deltaMos: number;
	
	    static createFrom(source: any = {}) {
	        return new WindowComparison(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.targetId = source["targetId"];
	        this.recent = this.convertValues(source["recent"], WindowStats);
	        this.previous = this.convertValues(source["previous"], WindowStats);
	        this.deltaJitterMs = source["deltaJitterMs"];
	        this.deltaLossPct = source["deltaLossPct"];
	        this.deltaMos = source["deltaMos"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace rdap {
	
	export class Contact {
	    roles?: string[];
	    name?: string;
	    org?: string;
	    email?: string;
	    phone?: string;
	    address?: string;
	
	    static createFrom(source: any = {}) {
	        return new Contact(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.roles = source["roles"];
	        this.name = source["name"];
	        this.org = source["org"];
	        this.email = source["email"];
	        this.phone = source["phone"];
	        this.address = source["address"];
	    }
	}
	export class DomainResult {
	    asked: string;
	    registered: string;
	    isExact: boolean;
	    tld?: string;
	    registry?: string;
	    handle?: string;
	    registrar?: string;
	    status?: string[];
	    nameservers?: string[];
	    contacts?: Contact[];
	    abuseEmail?: string;
	    remarks?: string[];
	    created?: string;
	    updated?: string;
	    expires?: string;
	    daysToExpiry?: number;
	    notes: string[];
	    disclosure: external.Disclosure;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new DomainResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.asked = source["asked"];
	        this.registered = source["registered"];
	        this.isExact = source["isExact"];
	        this.tld = source["tld"];
	        this.registry = source["registry"];
	        this.handle = source["handle"];
	        this.registrar = source["registrar"];
	        this.status = source["status"];
	        this.nameservers = source["nameservers"];
	        this.contacts = this.convertValues(source["contacts"], Contact);
	        this.abuseEmail = source["abuseEmail"];
	        this.remarks = source["remarks"];
	        this.created = source["created"];
	        this.updated = source["updated"];
	        this.expires = source["expires"];
	        this.daysToExpiry = source["daysToExpiry"];
	        this.notes = source["notes"];
	        this.disclosure = this.convertValues(source["disclosure"], external.Disclosure);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Result {
	    query: string;
	    rir: string;
	    rdapBaseURL: string;
	    handle?: string;
	    name?: string;
	    country?: string;
	    cidr?: string;
	    startAddress?: string;
	    endAddress?: string;
	    startASN?: number;
	    endASN?: number;
	    status?: string[];
	    contacts?: Contact[];
	    abuseEmail?: string;
	    nameservers?: string[];
	    remarks?: string[];
	    registered?: string;
	    lastChanged?: string;
	    disclosure: external.Disclosure;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.query = source["query"];
	        this.rir = source["rir"];
	        this.rdapBaseURL = source["rdapBaseURL"];
	        this.handle = source["handle"];
	        this.name = source["name"];
	        this.country = source["country"];
	        this.cidr = source["cidr"];
	        this.startAddress = source["startAddress"];
	        this.endAddress = source["endAddress"];
	        this.startASN = source["startASN"];
	        this.endASN = source["endASN"];
	        this.status = source["status"];
	        this.contacts = this.convertValues(source["contacts"], Contact);
	        this.abuseEmail = source["abuseEmail"];
	        this.nameservers = source["nameservers"];
	        this.remarks = source["remarks"];
	        this.registered = source["registered"];
	        this.lastChanged = source["lastChanged"];
	        this.disclosure = this.convertValues(source["disclosure"], external.Disclosure);
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace report {
	
	export class KeyValue {
	    key: string;
	    value: string;
	
	    static createFrom(source: any = {}) {
	        return new KeyValue(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.value = source["value"];
	    }
	}
	export class Meta {
	    generatedAt: string;
	    trazipVersion: string;
	    datasetVersions?: Record<string, string>;
	    config?: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new Meta(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.generatedAt = source["generatedAt"];
	        this.trazipVersion = source["trazipVersion"];
	        this.datasetVersions = source["datasetVersions"];
	        this.config = source["config"];
	    }
	}
	export class Table {
	    title: string;
	    columns: string[];
	    rows: string[][];
	
	    static createFrom(source: any = {}) {
	        return new Table(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.title = source["title"];
	        this.columns = source["columns"];
	        this.rows = source["rows"];
	    }
	}
	export class Section {
	    title: string;
	    summary?: string;
	    keyValues?: KeyValue[];
	    tables?: Table[];
	    notes?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Section(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.title = source["title"];
	        this.summary = source["summary"];
	        this.keyValues = this.convertValues(source["keyValues"], KeyValue);
	        this.tables = this.convertValues(source["tables"], Table);
	        this.notes = source["notes"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Report {
	    title: string;
	    meta: Meta;
	    summary: string;
	    sections: Section[];
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.title = source["title"];
	        this.meta = this.convertValues(source["meta"], Meta);
	        this.summary = source["summary"];
	        this.sections = this.convertValues(source["sections"], Section);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	

}

export namespace reputation {
	
	export class Signal {
	    source: string;
	    label: string;
	    detail: string;
	    confidence: string;
	    delta: number;
	
	    static createFrom(source: any = {}) {
	        return new Signal(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.source = source["source"];
	        this.label = source["label"];
	        this.detail = source["detail"];
	        this.confidence = source["confidence"];
	        this.delta = source["delta"];
	    }
	}
	export class Score {
	    addr: string;
	    value: number;
	    level: string;
	    signals?: Signal[];
	    freshness: string;
	    falsePositiveNote: string;
	
	    static createFrom(source: any = {}) {
	        return new Score(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.addr = source["addr"];
	        this.value = source["value"];
	        this.level = source["level"];
	        this.signals = this.convertValues(source["signals"], Signal);
	        this.freshness = source["freshness"];
	        this.falsePositiveNote = source["falsePositiveNote"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace rtcp {
	
	export class ReportBlock {
	    ssrc: number;
	    fractionLostPct: number;
	    cumulativeLost: number;
	    highestSeq: number;
	    jitterTicks: number;
	    lsr: number;
	    dlsr: number;
	
	    static createFrom(source: any = {}) {
	        return new ReportBlock(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ssrc = source["ssrc"];
	        this.fractionLostPct = source["fractionLostPct"];
	        this.cumulativeLost = source["cumulativeLost"];
	        this.highestSeq = source["highestSeq"];
	        this.jitterTicks = source["jitterTicks"];
	        this.lsr = source["lsr"];
	        this.dlsr = source["dlsr"];
	    }
	}
	export class Packet {
	    type: number;
	    ssrc: number;
	    ntpSeconds?: number;
	    ntpFraction?: number;
	    rtpTimestamp?: number;
	    packetCount?: number;
	    octetCount?: number;
	    reports?: ReportBlock[];
	
	    static createFrom(source: any = {}) {
	        return new Packet(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.ssrc = source["ssrc"];
	        this.ntpSeconds = source["ntpSeconds"];
	        this.ntpFraction = source["ntpFraction"];
	        this.rtpTimestamp = source["rtpTimestamp"];
	        this.packetCount = source["packetCount"];
	        this.octetCount = source["octetCount"];
	        this.reports = this.convertValues(source["reports"], ReportBlock);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace rtp {
	
	export class Snapshot {
	    ssrc: number;
	    payloadType: number;
	    clockRate: number;
	    clockAssumed: boolean;
	    received: number;
	    expected: number;
	    lost: number;
	    lossPct: number;
	    duplicates: number;
	    reordered: number;
	    jitterMs: number;
	    arrivalDurationMs: number;
	    rtpDurationMs: number;
	    clockSkewMs: number;
	
	    static createFrom(source: any = {}) {
	        return new Snapshot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ssrc = source["ssrc"];
	        this.payloadType = source["payloadType"];
	        this.clockRate = source["clockRate"];
	        this.clockAssumed = source["clockAssumed"];
	        this.received = source["received"];
	        this.expected = source["expected"];
	        this.lost = source["lost"];
	        this.lossPct = source["lossPct"];
	        this.duplicates = source["duplicates"];
	        this.reordered = source["reordered"];
	        this.jitterMs = source["jitterMs"];
	        this.arrivalDurationMs = source["arrivalDurationMs"];
	        this.rtpDurationMs = source["rtpDurationMs"];
	        this.clockSkewMs = source["clockSkewMs"];
	    }
	}

}

export namespace scandetect {
	
	export class Finding {
	    id: string;
	    kind: string;
	    severity: string;
	    confidence: number;
	    source: string;
	    target?: string;
	    port?: number;
	    distinct: number;
	    attempts: number;
	    firstSeen?: string;
	    lastSeen?: string;
	    durationSec: number;
	    ports?: number[];
	    targets?: string[];
	    summary: string;
	    explain: string;
	    mitre: string;
	
	    static createFrom(source: any = {}) {
	        return new Finding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.kind = source["kind"];
	        this.severity = source["severity"];
	        this.confidence = source["confidence"];
	        this.source = source["source"];
	        this.target = source["target"];
	        this.port = source["port"];
	        this.distinct = source["distinct"];
	        this.attempts = source["attempts"];
	        this.firstSeen = source["firstSeen"];
	        this.lastSeen = source["lastSeen"];
	        this.durationSec = source["durationSec"];
	        this.ports = source["ports"];
	        this.targets = source["targets"];
	        this.summary = source["summary"];
	        this.explain = source["explain"];
	        this.mitre = source["mitre"];
	    }
	}
	export class Result {
	    initialSyn: number;
	    vertical: number;
	    horizontal: number;
	    findings: Finding[];
	    truncated: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.initialSyn = source["initialSyn"];
	        this.vertical = source["vertical"];
	        this.horizontal = source["horizontal"];
	        this.findings = this.convertValues(source["findings"], Finding);
	        this.truncated = source["truncated"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace sdp {
	
	export class Codec {
	    payloadType: number;
	    name: string;
	    clockRate?: number;
	    channels?: number;
	    fmtp?: string;
	
	    static createFrom(source: any = {}) {
	        return new Codec(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.payloadType = source["payloadType"];
	        this.name = source["name"];
	        this.clockRate = source["clockRate"];
	        this.channels = source["channels"];
	        this.fmtp = source["fmtp"];
	    }
	}
	export class Media {
	    type: string;
	    port: number;
	    proto: string;
	    payloadTypes: number[];
	    connAddr?: string;
	    connFamily?: string;
	    direction: string;
	    codecs?: Record<number, Codec>;
	    candidates?: string[];
	    ptimeMs?: number;
	
	    static createFrom(source: any = {}) {
	        return new Media(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.port = source["port"];
	        this.proto = source["proto"];
	        this.payloadTypes = source["payloadTypes"];
	        this.connAddr = source["connAddr"];
	        this.connFamily = source["connFamily"];
	        this.direction = source["direction"];
	        this.codecs = this.convertValues(source["codecs"], Codec, true);
	        this.candidates = source["candidates"];
	        this.ptimeMs = source["ptimeMs"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SDP {
	    sessionConnAddr?: string;
	    sessionConnFamily?: string;
	    media: Media[];
	
	    static createFrom(source: any = {}) {
	        return new SDP(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sessionConnAddr = source["sessionConnAddr"];
	        this.sessionConnFamily = source["sessionConnFamily"];
	        this.media = this.convertValues(source["media"], Media);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace serviceaudit {
	
	export class ExposureResult {
	    expected: number[];
	    observed: number[];
	    unexpected: number[];
	    missing: number[];
	    compliant: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ExposureResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.expected = source["expected"];
	        this.observed = source["observed"];
	        this.unexpected = source["unexpected"];
	        this.missing = source["missing"];
	        this.compliant = source["compliant"];
	    }
	}
	export class Finding {
	    level: string;
	    category: string;
	    title: string;
	    detail: string;
	    evidence?: string;
	
	    static createFrom(source: any = {}) {
	        return new Finding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.level = source["level"];
	        this.category = source["category"];
	        this.title = source["title"];
	        this.detail = source["detail"];
	        this.evidence = source["evidence"];
	    }
	}
	export class Result {
	    target: string;
	    port: number;
	    protocol: string;
	    reachable: boolean;
	    metadata: Record<string, string>;
	    findings: Finding[];
	    durationMs: number;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target = source["target"];
	        this.port = source["port"];
	        this.protocol = source["protocol"];
	        this.reachable = source["reachable"];
	        this.metadata = source["metadata"];
	        this.findings = this.convertValues(source["findings"], Finding);
	        this.durationMs = source["durationMs"];
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace threatfeed {
	
	export class SourceInfo {
	    id: string;
	    name: string;
	    url: string;
	    fetchedAt?: string;
	    sha256?: string;
	    prefixCount: number;
	    present: boolean;
	    ageDays: number;
	
	    static createFrom(source: any = {}) {
	        return new SourceInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.url = source["url"];
	        this.fetchedAt = source["fetchedAt"];
	        this.sha256 = source["sha256"];
	        this.prefixCount = source["prefixCount"];
	        this.present = source["present"];
	        this.ageDays = source["ageDays"];
	    }
	}

}

export namespace throughput {
	
	export class Params {
	    sessionId: string;
	    proto: string;
	    direction: string;
	    durationMs: number;
	    streams: number;
	    bufferKB: number;
	    udpPacket: number;
	    targetMbps: number;
	    accessCode?: string;
	
	    static createFrom(source: any = {}) {
	        return new Params(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sessionId = source["sessionId"];
	        this.proto = source["proto"];
	        this.direction = source["direction"];
	        this.durationMs = source["durationMs"];
	        this.streams = source["streams"];
	        this.bufferKB = source["bufferKB"];
	        this.udpPacket = source["udpPacket"];
	        this.targetMbps = source["targetMbps"];
	        this.accessCode = source["accessCode"];
	    }
	}

}

export namespace tlsintel {
	
	export class CertInfo {
	    subject: string;
	    issuer: string;
	    dnsNames?: string[];
	    ipAddresses?: string[];
	    notBefore: string;
	    notAfter: string;
	    expired: boolean;
	    daysUntilExpiry: number;
	    serialNumber: string;
	    signatureAlgorithm: string;
	    publicKeyAlgorithm: string;
	    sha256Fingerprint: string;
	    isCA: boolean;
	
	    static createFrom(source: any = {}) {
	        return new CertInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.dnsNames = source["dnsNames"];
	        this.ipAddresses = source["ipAddresses"];
	        this.notBefore = source["notBefore"];
	        this.notAfter = source["notAfter"];
	        this.expired = source["expired"];
	        this.daysUntilExpiry = source["daysUntilExpiry"];
	        this.serialNumber = source["serialNumber"];
	        this.signatureAlgorithm = source["signatureAlgorithm"];
	        this.publicKeyAlgorithm = source["publicKeyAlgorithm"];
	        this.sha256Fingerprint = source["sha256Fingerprint"];
	        this.isCA = source["isCA"];
	    }
	}
	export class Result {
	    host: string;
	    port: number;
	    sni: string;
	    protocol: string;
	    cipherSuite: string;
	    alpn: string;
	    chain: CertInfo[];
	    validationOK: boolean;
	    validationError?: string;
	    durationMs: number;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.port = source["port"];
	        this.sni = source["sni"];
	        this.protocol = source["protocol"];
	        this.cipherSuite = source["cipherSuite"];
	        this.alpn = source["alpn"];
	        this.chain = this.convertValues(source["chain"], CertInfo);
	        this.validationOK = source["validationOK"];
	        this.validationError = source["validationError"];
	        this.durationMs = source["durationMs"];
	        this.err = source["err"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace update {
	
	export class Asset {
	    name: string;
	    url: string;
	    size: number;
	    sha256: string;
	
	    static createFrom(source: any = {}) {
	        return new Asset(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.url = source["url"];
	        this.size = source["size"];
	        this.sha256 = source["sha256"];
	    }
	}
	export class ReleaseInfo {
	    currentVersion: string;
	    latestVersion: string;
	    available: boolean;
	    // Go type: time
	    publishedAt: any;
	    notesUrl: string;
	    asset: Asset;
	    updaterAsset: Asset;
	
	    static createFrom(source: any = {}) {
	        return new ReleaseInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.currentVersion = source["currentVersion"];
	        this.latestVersion = source["latestVersion"];
	        this.available = source["available"];
	        this.publishedAt = this.convertValues(source["publishedAt"], null);
	        this.notesUrl = source["notesUrl"];
	        this.asset = this.convertValues(source["asset"], Asset);
	        this.updaterAsset = this.convertValues(source["updaterAsset"], Asset);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class StatusSnapshot {
	    status: string;
	    info?: ReleaseInfo;
	    downloaded?: number;
	    total?: number;
	    error?: string;
	    installPath?: string;
	    updaterPath?: string;
	    // Go type: time
	    lastCheck?: any;
	
	    static createFrom(source: any = {}) {
	        return new StatusSnapshot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.status = source["status"];
	        this.info = this.convertValues(source["info"], ReleaseInfo);
	        this.downloaded = source["downloaded"];
	        this.total = source["total"];
	        this.error = source["error"];
	        this.installPath = source["installPath"];
	        this.updaterPath = source["updaterPath"];
	        this.lastCheck = this.convertValues(source["lastCheck"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace voip {
	
	export class AuditFinding {
	    level: string;
	    category: string;
	    callId?: string;
	    summary: string;
	    evidence?: string;
	    confidence: number;
	
	    static createFrom(source: any = {}) {
	        return new AuditFinding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.level = source["level"];
	        this.category = source["category"];
	        this.callId = source["callId"];
	        this.summary = source["summary"];
	        this.evidence = source["evidence"];
	        this.confidence = source["confidence"];
	    }
	}
	export class AuditResult {
	    findings: AuditFinding[];
	    high: number;
	    medium: number;
	    low: number;
	
	    static createFrom(source: any = {}) {
	        return new AuditResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.findings = this.convertValues(source["findings"], AuditFinding);
	        this.high = source["high"];
	        this.medium = source["medium"];
	        this.low = source["low"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class MediaFinding {
	    level: string;
	    summary: string;
	
	    static createFrom(source: any = {}) {
	        return new MediaFinding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.level = source["level"];
	        this.summary = source["summary"];
	    }
	}
	export class SignalingHop {
	    address: string;
	    role: string;
	    userAgent?: string;
	    server?: string;
	    country?: string;
	    countryCode?: string;
	    asn?: number;
	    organization?: string;
	
	    static createFrom(source: any = {}) {
	        return new SignalingHop(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.address = source["address"];
	        this.role = source["role"];
	        this.userAgent = source["userAgent"];
	        this.server = source["server"];
	        this.country = source["country"];
	        this.countryCode = source["countryCode"];
	        this.asn = source["asn"];
	        this.organization = source["organization"];
	    }
	}
	export class CallParty {
	    address?: string;
	    userAgent?: string;
	    server?: string;
	    country?: string;
	    countryCode?: string;
	    asn?: number;
	    organization?: string;
	
	    static createFrom(source: any = {}) {
	        return new CallParty(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.address = source["address"];
	        this.userAgent = source["userAgent"];
	        this.server = source["server"];
	        this.country = source["country"];
	        this.countryCode = source["countryCode"];
	        this.asn = source["asn"];
	        this.organization = source["organization"];
	    }
	}
	export class RTCPSenderSummary {
	    packetCount: number;
	    octetCount: number;
	    ntpSeconds: number;
	    ntpFraction: number;
	    rtpTimestamp: number;
	
	    static createFrom(source: any = {}) {
	        return new RTCPSenderSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.packetCount = source["packetCount"];
	        this.octetCount = source["octetCount"];
	        this.ntpSeconds = source["ntpSeconds"];
	        this.ntpFraction = source["ntpFraction"];
	        this.rtpTimestamp = source["rtpTimestamp"];
	    }
	}
	export class RTCPReceiverSummary {
	    fractionLostPct: number;
	    cumulativeLost: number;
	    highestSeq: number;
	    jitterTicks: number;
	    jitterMs?: number;
	    lsr?: number;
	    dlsr?: number;
	
	    static createFrom(source: any = {}) {
	        return new RTCPReceiverSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fractionLostPct = source["fractionLostPct"];
	        this.cumulativeLost = source["cumulativeLost"];
	        this.highestSeq = source["highestSeq"];
	        this.jitterTicks = source["jitterTicks"];
	        this.jitterMs = source["jitterMs"];
	        this.lsr = source["lsr"];
	        this.dlsr = source["dlsr"];
	    }
	}
	export class RTCPSummary {
	    estimatedRttMs?: number;
	    estimatedRttUnavailableReason?: string;
	    receiver?: RTCPReceiverSummary;
	    sender?: RTCPSenderSummary;
	
	    static createFrom(source: any = {}) {
	        return new RTCPSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.estimatedRttMs = source["estimatedRttMs"];
	        this.estimatedRttUnavailableReason = source["estimatedRttUnavailableReason"];
	        this.receiver = this.convertValues(source["receiver"], RTCPReceiverSummary);
	        this.sender = this.convertValues(source["sender"], RTCPSenderSummary);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class MOSEstimate {
	    score: number;
	    formula: string;
	    limitations: string[];
	
	    static createFrom(source: any = {}) {
	        return new MOSEstimate(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.score = source["score"];
	        this.formula = source["formula"];
	        this.limitations = source["limitations"];
	    }
	}
	export class StreamInfo {
	    callId?: string;
	    ssrc: number;
	    src: string;
	    dst: string;
	    payloadType: number;
	    codecName?: string;
	    clockRate?: number;
	    mediaType?: string;
	    stats: rtp.Snapshot;
	    mos?: MOSEstimate;
	    rtcpSeen: boolean;
	    rtcpReports?: rtcp.Packet[];
	    rtcp?: RTCPSummary;
	    dtmfDigits?: string;
	    // Go type: time
	    firstSeen?: any;
	    // Go type: time
	    lastSeen?: any;
	    ptimeMs?: number;
	    audioStatus?: string;
	    audioStatusDetail?: string;
	    direction?: string;
	
	    static createFrom(source: any = {}) {
	        return new StreamInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.callId = source["callId"];
	        this.ssrc = source["ssrc"];
	        this.src = source["src"];
	        this.dst = source["dst"];
	        this.payloadType = source["payloadType"];
	        this.codecName = source["codecName"];
	        this.clockRate = source["clockRate"];
	        this.mediaType = source["mediaType"];
	        this.stats = this.convertValues(source["stats"], rtp.Snapshot);
	        this.mos = this.convertValues(source["mos"], MOSEstimate);
	        this.rtcpSeen = source["rtcpSeen"];
	        this.rtcpReports = this.convertValues(source["rtcpReports"], rtcp.Packet);
	        this.rtcp = this.convertValues(source["rtcp"], RTCPSummary);
	        this.dtmfDigits = source["dtmfDigits"];
	        this.firstSeen = this.convertValues(source["firstSeen"], null);
	        this.lastSeen = this.convertValues(source["lastSeen"], null);
	        this.ptimeMs = source["ptimeMs"];
	        this.audioStatus = source["audioStatus"];
	        this.audioStatusDetail = source["audioStatusDetail"];
	        this.direction = source["direction"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TimelineEvent {
	    time: string;
	    src: string;
	    dst: string;
	    summary: string;
	    retransmission?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new TimelineEvent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.time = source["time"];
	        this.src = source["src"];
	        this.dst = source["dst"];
	        this.summary = source["summary"];
	        this.retransmission = source["retransmission"];
	    }
	}
	export class Call {
	    callId: string;
	    from?: string;
	    to?: string;
	    timeline: TimelineEvent[];
	    established: boolean;
	    setupMs?: number;
	    terminated: boolean;
	    durationSec?: number;
	    failureCode?: number;
	    failureReason?: string;
	    probableCause?: string;
	    retransmissions: number;
	    authenticated: boolean;
	    natIssue?: boolean;
	    sdpOffer?: sdp.SDP;
	    sdpAnswer?: sdp.SDP;
	    streams?: StreamInfo[];
	    unidirectional?: boolean;
	    caller?: CallParty;
	    callee?: CallParty;
	    signalingPath?: SignalingHop[];
	    signalingPathComplete?: boolean;
	    failureOrigin?: string;
	    mediaFindings?: MediaFinding[];
	    diagnosis?: model.Assessment;
	
	    static createFrom(source: any = {}) {
	        return new Call(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.callId = source["callId"];
	        this.from = source["from"];
	        this.to = source["to"];
	        this.timeline = this.convertValues(source["timeline"], TimelineEvent);
	        this.established = source["established"];
	        this.setupMs = source["setupMs"];
	        this.terminated = source["terminated"];
	        this.durationSec = source["durationSec"];
	        this.failureCode = source["failureCode"];
	        this.failureReason = source["failureReason"];
	        this.probableCause = source["probableCause"];
	        this.retransmissions = source["retransmissions"];
	        this.authenticated = source["authenticated"];
	        this.natIssue = source["natIssue"];
	        this.sdpOffer = this.convertValues(source["sdpOffer"], sdp.SDP);
	        this.sdpAnswer = this.convertValues(source["sdpAnswer"], sdp.SDP);
	        this.streams = this.convertValues(source["streams"], StreamInfo);
	        this.unidirectional = source["unidirectional"];
	        this.caller = this.convertValues(source["caller"], CallParty);
	        this.callee = this.convertValues(source["callee"], CallParty);
	        this.signalingPath = this.convertValues(source["signalingPath"], SignalingHop);
	        this.signalingPathComplete = source["signalingPathComplete"];
	        this.failureOrigin = source["failureOrigin"];
	        this.mediaFindings = this.convertValues(source["mediaFindings"], MediaFinding);
	        this.diagnosis = this.convertValues(source["diagnosis"], model.Assessment);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	
	
	
	export class Result {
	    calls: Call[];
	    totalCalls: number;
	    established: number;
	    failed: number;
	    audit: AuditResult;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.calls = this.convertValues(source["calls"], Call);
	        this.totalCalls = source["totalCalls"];
	        this.established = source["established"];
	        this.failed = source["failed"];
	        this.audit = this.convertValues(source["audit"], AuditResult);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	

}

export namespace webintel {
	
	export class ContactedEndpoint {
	    hostname?: string;
	    ip: string;
	    country?: string;
	    asn?: number;
	    org?: string;
	    isPublic: boolean;
	    classes: string[];
	
	    static createFrom(source: any = {}) {
	        return new ContactedEndpoint(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hostname = source["hostname"];
	        this.ip = source["ip"];
	        this.country = source["country"];
	        this.asn = source["asn"];
	        this.org = source["org"];
	        this.isPublic = source["isPublic"];
	        this.classes = source["classes"];
	    }
	}
	export class DNSChainEntry {
	    type: string;
	    name: string;
	    value: string;
	    ttl: number;
	
	    static createFrom(source: any = {}) {
	        return new DNSChainEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.name = source["name"];
	        this.value = source["value"];
	        this.ttl = source["ttl"];
	    }
	}
	export class Error {
	    code: string;
	    stage: string;
	    friendlyMessageES: string;
	    friendlyMessageEN: string;
	    technicalDetail: string;
	    retryable: boolean;
	    static createFrom(source: any = {}) {
	        return new Error(source);
	    }
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.code = source["code"];
	        this.stage = source["stage"];
	        this.friendlyMessageES = source["friendlyMessageES"];
	        this.friendlyMessageEN = source["friendlyMessageEN"];
	        this.technicalDetail = source["technicalDetail"];
	        this.retryable = source["retryable"];
	    }
	}
	export class GraphEdge {
	    from: string;
	    to: string;
	    kind: string;
	
	    static createFrom(source: any = {}) {
	        return new GraphEdge(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.from = source["from"];
	        this.to = source["to"];
	        this.kind = source["kind"];
	    }
	}
	export class GraphNode {
	    id: string;
	    kind: string;
	    label: string;
	
	    static createFrom(source: any = {}) {
	        return new GraphNode(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.kind = source["kind"];
	        this.label = source["label"];
	    }
	}
	export class Graph {
	    nodes: GraphNode[];
	    edges: GraphEdge[];
	
	    static createFrom(source: any = {}) {
	        return new Graph(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.nodes = this.convertValues(source["nodes"], GraphNode);
	        this.edges = this.convertValues(source["edges"], GraphEdge);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	export class Result {
	    inputURL: string;
	    normalizedURL: string;
	    resolver: string;
	    dnsChain: DNSChainEntry[];
	    http: httpintel.Result;
	    tls?: tlsintel.Result;
	    contactedEndpoints: ContactedEndpoint[];
	    extractedHostnames: string[];
	    extractedIPs: string[];
	    graph: Graph;
	    durationMs: number;
	    err?: string;
	    error?: Error;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.inputURL = source["inputURL"];
	        this.normalizedURL = source["normalizedURL"];
	        this.resolver = source["resolver"];
	        this.dnsChain = this.convertValues(source["dnsChain"], DNSChainEntry);
	        this.http = this.convertValues(source["http"], httpintel.Result);
	        this.tls = this.convertValues(source["tls"], tlsintel.Result);
	        this.contactedEndpoints = this.convertValues(source["contactedEndpoints"], ContactedEndpoint);
	        this.extractedHostnames = source["extractedHostnames"];
	        this.extractedIPs = source["extractedIPs"];
	        this.graph = this.convertValues(source["graph"], Graph);
	        this.durationMs = source["durationMs"];
	        this.err = source["err"];
	        this.error = this.convertValues(source["error"], Error);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace wifi {
	
	export class IfaceStatus {
	    description: string;
	    connected: boolean;
	    ssid?: string;
	
	    static createFrom(source: any = {}) {
	        return new IfaceStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.description = source["description"];
	        this.connected = source["connected"];
	        this.ssid = source["ssid"];
	    }
	}
	export class Network {
	    ssid: string;
	    bssid?: string;
	    signalPct: number;
	    rssiDbm?: number;
	    channel?: number;
	    band?: string;
	    security: string;
	    connectable: boolean;
	    apCount: number;
	
	    static createFrom(source: any = {}) {
	        return new Network(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ssid = source["ssid"];
	        this.bssid = source["bssid"];
	        this.signalPct = source["signalPct"];
	        this.rssiDbm = source["rssiDbm"];
	        this.channel = source["channel"];
	        this.band = source["band"];
	        this.security = source["security"];
	        this.connectable = source["connectable"];
	        this.apCount = source["apCount"];
	    }
	}
	export class PostureFinding {
	    level: string;
	    category: string;
	    ssid?: string;
	    bssid?: string;
	    summary: string;
	    evidence?: string;
	
	    static createFrom(source: any = {}) {
	        return new PostureFinding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.level = source["level"];
	        this.category = source["category"];
	        this.ssid = source["ssid"];
	        this.bssid = source["bssid"];
	        this.summary = source["summary"];
	        this.evidence = source["evidence"];
	    }
	}
	export class PostureResult {
	    score: number;
	    networks: number;
	    baselineCreated: boolean;
	    findings: PostureFinding[];
	    assessedAt: string;
	
	    static createFrom(source: any = {}) {
	        return new PostureResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.score = source["score"];
	        this.networks = source["networks"];
	        this.baselineCreated = source["baselineCreated"];
	        this.findings = this.convertValues(source["findings"], PostureFinding);
	        this.assessedAt = source["assessedAt"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}
