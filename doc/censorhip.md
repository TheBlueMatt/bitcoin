One key assumption in the safe use of the Bitcoin network is at least one path to receive block data from the honest
majority of Bitcoin miners. This assumption can be violated in many different ways, including:

 * A network outage,
 * ISP (or your ISP's ISP, or...) censorship of Bitcoin traffic,
 * Partial censorship of Bitcoin traffic on/to some networks, but not others
   (eg censorship at a country's border/major peering points within a country)
 * Eclipse attacks, which can come in several forms, and may be best combined with above attacks:
   * Address database poisoning to cause a node to only connect to an attacker's nodes,
   * A bug causing Bitcoin Core to fetch block data from only some of its peers.

Bitcoin Core supports several features designed to assist in detection and circumvention of some of these attacks,
described below.
Note that, in general, Bitcoin Core does not prevent those with visibility into your network traffic (eg your ISP, your
ISP's ISP, your country's state intelligence service, etc) from learning that you are operating a Bitcoin node. While
the -onlynet=onion option (in combination with -tor configured to point to a local Tor proxy operating using bridges)
may make this more difficult, the traffic pattern of Bitcoin use (most notably traffic spikes around the time new blocks
are found) may still expose the presence of a Bitcoin node.

 * Headers-over-DNS

   This module fetches headers using the DNS. While accessing the DNS using default ISP DNS resolvers is often censored,
   new approaches to connecting to DNS resolvers (eg DNS-over-TLS) are designed to allow users to bypass such censorship
   by moving to an alternative trusted third party DNS resolver.
   If you have configured your system resolver to use one of these services, enabling this module may allow detection of
   other forms of censorship. The option -headersfetchdns must be configured with a domain name which encodes such
   headers in the correct format.
   The operator(s) of the domain, as well as your DNS resolver operator may learn that you are operating a Bitcoin node.
   bitcoinheaders.net is hosted by several interested parties and should provide a good default value if you wish to use
   this module.

  * Blocks-over-HTTP

    stunnel is great! (kinda, can we use it for domain-fronting?)
    TODO!

  * Headers-over-Wireless-Broadcast

    This module broadcasts, receives, and fetches headers over an abstract wireless broadcast medium. It supports several
    different devices and modes to enable use on different bands and with different censorship properties.
    It is enabled by setting the -radiobroadcastheaders option to a series of parameters, separated by ':'s.
    The first parameter represents a protocol (see below). The second parameter always represents a "mode" setting, which
    can be one of "rw", "ro", or "wo" to indicate read/write, read-only, and write-only operation. In read/write mode,
    if we are missing a header's parent header, we can request it on the air, however the device which broadcasted the
    header must be in read/write mode as well (and be able to hear our request).
    In read-only mode, the presence of a Bitcoin node should not be detectable (depending on your wireless hardware).
    The last parameter must always be the path to a device (eg a character device or named pipe) which is used to 
    commnicate with the radio hardware.

    The protocol can be one of:
    * A LoRa device, which can be good for links up to a mile or two in urban areas and up to ten or so miles in rural
      areas.
      The protocol parameter should be set to lora and the parameters after mode are <region>:<noise>:<txp>:<device>.
        <region> can either be "na" or "eu" for North America or Europe, selecting a frequency band of either
                 920.5-920.75 MHz in NA or 869.4-869.65 Mhz in EU. Further, in EU mode a restriction of transmitting no
                 more than 10% in any given day is enforced.
                 It is up to you to ensure you comply with the regulatory power and spectrum limitations in your area.
        <noise> is 1-4 and indicates relative noise immunity. In general, set to 4 for urban areas, 1 for rural areas.
        <device> currently must be "rnode" to indicate an RNode device.
        <txp> is only for "rnode" devices and represents the txpower between 0 and 17 (depending on the model).
     * "hexpipe" indicates an arbitrary device which receives or sends messages in hex-encoded form, one line at a time.
       The device must handle its own framing, as messages are expected to be of the correct length on the receive end.
     * "rawframed" indicates an arbitrary device which receives or sends messages in raw form.
       Framing is added as appropriate, changing the format of the messages on the air slightly from hexpipe and LoRa
       modes. Specifically, while all three modes begin with the 4-byte network magic, "rawframed" mode includes a
       single byte length field thereafter, indicating the length of the message (not including the magic or length
       fields). Thus, to translate between the two, remove the 5th byte (the length-of-remaining-message byte) from
       rawframed mode data.


    For all modes, no forward error correction is provided, and the on-the-air framing should likely include some
    (though checksumming is generally not required, as the data is validated using Bitcoin consensus rules). Note that
    LoRa has its own error correction built in.

  * Parallel P2P client

    This module acts similarly to the existing P2P client in Bitcoin Core, with a few important differences. Primarily,
    it prioritizes simplicity and correctness over effeciency, giving the existing P2P client a chance to fetch
    consensus data before acting. When it does notice that data has been missing for some time (for example if one of
    the above modules received a header but we haven't been able to fetch the block for it), it kicks into high gear
    and agressively searches for new peers and potentially redundantly downloading data until it has the blocks it is
    missing.
    For this reason, if some censorship attack occurs, this module may over-correct and make it particularly obvious
    that you are operating a Bitcoin node to many third-parties. Still, for certain classes of attacks (eg the "bug in
    the existing client" class of eclipse attacks), this is a critical countermeasure. Thus, unlike the above modules,
    it is enabled by default. It can be disabled with the -noparallelp2p option.
