# zeek-dronebl-dnsbl

This [Zeek](https://zeek.org)'s script allows you to check IPs against
[DroneBL](https://dronebl.org/)'s database.

You can find some **documentation** in the *export* section of
[dronebl-dnsbl/main.bro](dronebl-dnsbl/main.bro).
An example of usage is avaiable in [main.bro](main.bro).

If imported without redefining any option, you can use this module to manually
check IPs using `check_ip(addr) : bool` or `classify_ip(addr) : ThreatClass`.

It is still a work in progress, thus some functionality is missing.

**Written and tested for Zeek/Bro version 2.6.1**

## License

Read the file [LICENSE.txt](LICENSE.txt)

## Author

Jacopo (antipatico) Scannella
