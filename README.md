# SharpAdidnsdump

SharpAdidnsdump is a c# implementation of Dirk-jan Mollema research: [Getting in the zone dumping active directory dns with adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/).

All the credits go to Dirk-jan Mollema and his research.

# Features

Enumerate all hosts with IPs via AD LDAP and DNS query.

The first step is to list the zones available in DomainDnsZone using the filter (&(objectClass = DnsZone)(!(DC=*arpa))(!(DC=RootDNSServers))).

For each zone it is possible to list all Host objects with the filter (&(!(ObjectClass=DnsZone))(!(DC=@))(!(DC=*arpa))(!(DC=*DNSZones))) changing the RootDn of the query. It is necessary (!(ObjectClass=DnsZone)) because if the filter were used (objectClass=DnsNode) the hidden elements would be excluded.

Some of the records present via LDAP can be listed as unlisted.
In my implementation I resolve the visibility of these records with the parsoing of the Path property of the SearchResult object.

### Usage

SharpAdidnsdumpis.exe dc-address


# References

[Getting in the zone dumping active directory dns with adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/).

[Adidnsdump](https://github.com/dirkjanm/adidnsdump)



Feel free to contact me at: [@b4rtik](https://twitter.com/b4rtik)


