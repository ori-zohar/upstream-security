package upstream

// ips are provided in CIDR notation
class IpBlocker(suspiciousIps: List<String>) {

    // this is a sorted and merged list of the suspicious ip ranges
    private val suspiciousIps: List<IpRange> = suspiciousIps.map { it.toIpRange() }.merge()

    fun isAllowed(incomingIp: String): Boolean {
        val numericIp = incomingIp.toNumericIp()
        // it searches for the placement of the numericIp in the suspiciousIps list
        val index = suspiciousIps.binarySearch { it.fromNumericIp.compareTo(numericIp) }
        // if we found an index, then it means we have a range starting with that value, it is not allowed
        if (index >= 0) return false;
        // we found the insertion point
        val insertionPoint = -(index+1)
        // if the insertion point is at the beginning of the array then its smaller than all the suspicious ips
        if (insertionPoint == 0) return true
        // otherwise we should check if the ip is within range of the item in insertionPoint-1
        return numericIp !in suspiciousIps[insertionPoint-1]
    }
}

/**
 * This function takes a list of IpRanges
 * - sorts the list
 * - merges any intersecting ranges
 *
 * @return sorted merged list of IpRanges
 */
fun List<IpRange>.merge(): List<IpRange> {
    val sorted = this.sortedBy { it.fromNumericIp }
    val merged = mutableListOf<IpRange>()
    var from = sorted.first().fromNumericIp
    var to = sorted.first().toNumericIp
    sorted.subList(1, sorted.size).forEach {
        if (to < it.fromNumericIp) {
            merged.add(IpRange(from, to))
            from = it.fromNumericIp
        }
        to = it.toNumericIp
    }
    merged.add(IpRange(from, to))
    return merged
}

