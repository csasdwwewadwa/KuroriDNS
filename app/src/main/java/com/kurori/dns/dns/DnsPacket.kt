package com.kurori.dns.dns

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class ParsedDnsQuery(
    val domain: String,
    val dnsMessage: ByteArray,
    val sourceAddress: ByteArray,
    val destinationAddress: ByteArray,
    val sourcePort: Int,
    val ipIdentifier: Int
)

object DnsPacket {
    fun parseIpv4Udp(packet: ByteArray, packetLength: Int): ParsedDnsQuery? {
        if (packetLength < 28 || packet[0].toInt() ushr 4 and 0x0f != 4) return null
        val headerLength = (packet[0].toInt() and 0x0f) * 4
        val totalLength = readU16(packet, 2)
        if (headerLength < 20 || totalLength > packetLength || totalLength < headerLength + 8) return null
        if (packet[9].toInt() and 0xff != 17) return null
        if (readU16(packet, 6) and 0x3fff != 0) return null

        val udpOffset = headerLength
        val udpLength = readU16(packet, udpOffset + 4)
        if (readU16(packet, udpOffset + 2) != 53 || udpLength < 20) return null
        if (udpOffset + udpLength > totalLength) return null

        val dnsOffset = udpOffset + 8
        val dnsLength = udpLength - 8
        val dns = packet.copyOfRange(dnsOffset, dnsOffset + dnsLength)
        val domain = parseQuestionName(dns) ?: return null

        return ParsedDnsQuery(
            domain = domain,
            dnsMessage = dns,
            sourceAddress = packet.copyOfRange(12, 16),
            destinationAddress = packet.copyOfRange(16, 20),
            sourcePort = readU16(packet, udpOffset),
            ipIdentifier = readU16(packet, 4)
        )
    }

    fun responsePacket(query: ParsedDnsQuery, dnsResponse: ByteArray): ByteArray {
        val udpLength = 8 + dnsResponse.size
        val packet = ByteArray(20 + udpLength)
        packet[0] = 0x45
        putU16(packet, 2, packet.size)
        putU16(packet, 4, query.ipIdentifier)
        putU16(packet, 6, 0x4000)
        packet[8] = 64
        packet[9] = 17
        query.destinationAddress.copyInto(packet, 12)
        query.sourceAddress.copyInto(packet, 16)
        putU16(packet, 10, ipv4Checksum(packet, 20))

        putU16(packet, 20, 53)
        putU16(packet, 22, query.sourcePort)
        putU16(packet, 24, udpLength)
        dnsResponse.copyInto(packet, 28)
        return packet
    }

    fun errorResponse(query: ByteArray, rcode: Int): ByteArray? {
        if (query.size < 12 || readU16(query, 4) != 1) return null
        val questionEnd = questionEnd(query) ?: return null
        val response = query.copyOfRange(0, questionEnd)
        val flags = readU16(response, 2)
        putU16(response, 2, (flags and 0x7900) or 0x8080 or (rcode and 0x0f))
        putU16(response, 6, 0)
        putU16(response, 8, 0)
        putU16(response, 10, 0)
        return response
    }

    private fun parseQuestionName(message: ByteArray): String? {
        if (message.size < 17 || readU16(message, 4) != 1) return null
        val labels = mutableListOf<String>()
        var offset = 12
        while (offset < message.size) {
            val length = message[offset++].toInt() and 0xff
            if (length == 0) break
            if (length and 0xc0 != 0 || length > 63 || offset + length > message.size) return null
            labels.add(String(message, offset, length, Charsets.US_ASCII).lowercase())
            offset += length
        }
        if (labels.isEmpty() || offset + 4 > message.size) return null
        return labels.joinToString(".")
    }

    private fun questionEnd(message: ByteArray): Int? {
        var offset = 12
        while (offset < message.size) {
            val length = message[offset++].toInt() and 0xff
            if (length == 0) return if (offset + 4 <= message.size) offset + 4 else null
            if (length and 0xc0 != 0 || length > 63 || offset + length > message.size) return null
            offset += length
        }
        return null
    }

    private fun readU16(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private fun ipv4Checksum(packet: ByteArray, length: Int): Int {
        val buffer = ByteBuffer.wrap(packet, 0, length).order(ByteOrder.BIG_ENDIAN)
        var sum = 0L
        while (buffer.remaining() >= 2) sum += buffer.short.toInt() and 0xffff
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv().toInt() and 0xffff
    }
}