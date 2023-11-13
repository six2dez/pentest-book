# Subdomain tools review

## Intro

**What?** This is a December 2020 subdomain tools review made by myself. I have compared and review every tool one by one and obtained a general view of the "state-of-the-art" of the most used subdomain tools.&#x20;

**Why?** Sometimes I have doubts if I am actually finding all the subdomains when I start hunting and if the tool I use will find them all. This is the review that I would like to have read before deciding on one tool or another.

**How?** As the main objective is to find subdomains, I have launched the tools against a small scope (zego.com), a medium scope (tiktok.com) and a large one (twitter.com) to see how the different tools respond.

Having different tools and different approaches I have compared the tools by typology, like this:

* **Passive:** It relies on third-party services with which it collects the largest possible number of subdomains, dead or alive. The problem with this approach is that you can find numerous subdomains, but many of them may be prehistoric, but in return they do it very quickly.
* **Active**: From any source, for example third-party sources of the passive approach, it verifies through DNS requests (or in any other way) if the subdomain is alive or not. This approach takes a little longer than the passive one, but the results it generates are almost entirely useful.
* **Bruteforce**: From a wordlist and a domain, it makes DNS requests for each word along with the domain. The advantage of this approach is that the results obtained are always real, but it depends entirely on the quality of the wordlist.
* **Alterations/permutations**: In this case, from a list of subdomains and a list of alterations or permutations, a new list of subdomains is generated that are verified through DNS requests. With this approach you can find subdomains that with the rest would be impossible.

The integrations with third-party services I have tried to use as many as the tool allows me for free. All scans have been done against the same targets and with the same bruteforcing wordlists and alteration wordlists.

* Resolvers: [danielmiessler/Miscellaneous/dns-resolvers.txt](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/dns-resolvers.txt)
* Bruteforce: [danielmiessler/Discovery/DNS/subdomains-top1million-20000.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-20000.txt)
* Alterations: [altdns/words.txt](https://github.com/infosec-au/altdns/blob/master/words.txt)

{% hint style="info" %}
This is not intended to be a serious investigation, a technical paper, or anything like that, just a series of tests that I have done for fun. The results shown are my opinion and if at any time you don't like them, or you don't agree, you can stop reading or explain to me how I could have done it better 😉
{% endhint %}

All the results of my runs and tests are posted [here](https://docs.google.com/spreadsheets/d/1Fa\_dv4jnMCDcpa\_RQy12TpEZQNo1l8KsDFJscPjnePo/edit?usp=sharing), it has four sheets (Summary, Small scope, Medium Scope and Large Scope).

{% embed url="https://docs.google.com/spreadsheets/d/1Fa_dv4jnMCDcpa_RQy12TpEZQNo1l8KsDFJscPjnePo/edit?usp=sharing" %}

In addition, the results of all the scans that I have done have been uploaded to a folder that you can see [here](https://drive.google.com/drive/folders/1urkJUrHHal3-UYB0R-3g8VWSBNGVP1d7?usp=sharing).

## Tools

Small summary of each tool with the features and results that I got. This section not follows any special order.

### [amass](https://github.com/OWASP/Amass)

* Author: [OWASP](https://github.com/OWASP) (mainly [caffix](https://github.com/caffix)).
* Language: Go.
* Type: Passive, Active, Bruteforce, Alterations (only Active and Passive tested here).
* Api Keys added: 16 (AlienVault, Binary Edge, Censys, Chaos, Cloudflare, Facebook, Github, NetworksDB, PassiveTotal, ReconDev, SecurityTrails, Shodan, SpySe, UrlScan, VirusTotal, WhoIsXML).

Well known tool for the enumeration of subdomains. It's basically an all-in-one because it does everything, plus many other things apart from the subdomains. In the case of this tool, I have only analyzed the passive and active approaches because there is no way to do a unit analysis for brute force or alterations without consulting third-party services previously (or at least I have not known how to do it).

#### Pros

* Lot of third-party integrations
* Swiss army knife for subdomains enumeration, all the functionalities you can think of and more.
* It added active subdomains that none of the other tools managed to add.

#### Cons

* Not fast at all.
* Sometimes usability is confusing due to the large number of options

### [Sublist3r](https://github.com/aboul3la/Sublist3r)

* Author: [aboul3la](https://github.com/aboul3la)
* Language: Python
* Type: Passive, Bruteforce (only Passive tested here).
* Api Keys added: 0.

Widely used on a lot of tools since it's been around since 2015, plus you don't need to add additional API keys. One problem that I found with this tool is that it does not allow resolving subdomains found passively, but it does incorporate subbrute for bruteforce, which it does DNS resolution, but on the contrary it does not allow to specify a different wordlist, for this reason don't test the bruteforce feature.

#### Pros

* Really fast.
* Include subbrute for bruteforcing.
* Include port scan.

#### Cons

* Few results compared to others.
* Limited features, such as bruteforce without the ability to specify a custom wordlist.

### [crobat](https://github.com/Cgboal/SonarSearch)

* Author: [Cgboal](https://github.com/Cgboal)
* Language: Go
* Type: Passive
* Api Keys added: 0.

It is basically the easiest way to consult the Rapid7's Project Sonar Database.&#x20;

#### Pros

* Consults in one of the best data sources.
* Ultra-fast.

#### Cons

* Nothing in particular, does a very specific thing and does it well.

### [chaos](https://github.com/projectdiscovery/chaos-client)

* Author: [projectdiscovery](https://github.com/projectdiscovery)
* Language: Go
* Type: Passive
* Api Keys added: 1 (Chaos).

Official client to consult the Chaos database. It is mainly oriented for bug bounty, it contains the database of all the programs.

#### Pros

* Ultra-fast.
* Allow to update dataset with your own findings.
* Multiple filters and outputs options.

#### Cons

* API Key limited to invitations.

### [subfinder](https://github.com/projectdiscovery/subfinder)

* Author: [projectdiscovery](https://github.com/projectdiscovery)
* Language: Go
* Type: Passive and Active.
* Api Keys added: 13 (BinaryEdge, Censys, Chaos, DnsDB, GitHub, PassiveTotal, ReconDev, Robtex, SecurityTrails, Shodan, SpySe, UrlScan, VirusTotal).

The definitive subdomain tool from projectdiscovery is the one that gets the most results in passive and active mode. Simply the best.

#### Pros

* Fast compared with others with similar number of integrations.
* Use 35 third-party services in total.
* Lot of options for search, filters and output.

#### Cons

* Amass got a few subdomains that subfinder missed only in the large scope.

### [altdns](https://github.com/infosec-au/altdns)

* Author: [infosec-au](https://github.com/infosec-au)
* Language: Python
* Type: Alterations.

The most popular tool for subdomain alteration and resolution. It currently has a [bug ](https://github.com/infosec-au/altdns/issues/29#issuecomment-656686014)that needs to be fixed to make the tool work.

#### Pros

* Allows set custom resolver.
* Output include CNAME.

#### Cons

* Really really slow.
* Not the best alteration wordlist.

### [shuffledns](https://github.com/projectdiscovery/shuffledns)

* Author: [projectdiscovery](https://github.com/projectdiscovery)
* Language: Go
* Type: Bruteforce.

Fastest bruteforce and resolution subdomain tool by projectdisovery (yes, again). It's actually a massdns wrapper inside, but it makes it much easier to use with a simple syntax.

#### Pros

* Fastest.
* Allows directly massdns output.
* Wildcard support.

#### Cons

* In some cases, it missed some subdomains that the rest did.

### [assetfinder](https://github.com/tomnomnom/assetfinder)

* Author: [tomnomnom](https://github.com/tomnomnom)
* Language: Go
* Type: Passive.
* Api Keys added: 3 (Facebook, VirusTotal, SpySe).

This tool is aimed to find domains and subdomains related to a given domain. Related means, not just subdomains, but other which could be third-party urls for example.

#### Pros

* Really fast for the amount of services integrated.
* 9 services included.
* That "related" feature.

#### Cons

* No results not found by others.

### [waybackurls](https://github.com/tomnomnom/waybackurls)

* Author: [tomnomnom](https://github.com/tomnomnom)
* Language: Go
* Type: Passive.
* Api Keys added: 0.

The main purpose of this tool is to fetch urls from WaybackMachine, but is widely used to retrieve subdomains too.

#### Pros

* Fast.

#### Cons

* Not subdomains feature, you have to filter with some tool like [unfurl](https://github.com/tomnomnom/unfurl) or grep.

### [github-subdomains](https://github.com/gwen001/github-subdomains)

* Author: [gwen001](https://github.com/gwen001)
* Language: Go
* Type: Passive.
* Api Keys added: 1 (GitHub).

The main purpose of this tool is to fetch urls from WaybackMachine, but is widely used to retrieve subdomains too.

#### Pros

* Fast.
* GitHub is always a useful source.

#### Cons

* With some common names or companies could be very slow.

### [dnscan](https://github.com/rbsec/dnscan)

* Author: [rbsec](https://github.com/rbsec)
* Language: Python
* Type: Bruteforce.

Actively updated tool for bruteforce with some nice features like transfer zone checker and recursiveness.

#### Pros

* Transfer zone feature.
* Custom insertion points.
* Provided with 7 wordlists.

#### Cons

* Python 2.

### [gobuster](https://github.com/OJ/gobuster)

* Author: [OJ](https://github.com/OJ)
* Language: Go
* Type: Bruteforce.

Mainly known for web fuzzing, it also has the option to scan for DNS. It's one of the must-have tools in the community.

#### Pros

* Wildcard support.
* Option to show CNAME or IP.

#### Cons

* None really.

### [knock](https://github.com/guelfoweb/knock)

* Author: [guelfoweb](https://github.com/guelfoweb)
* Language: Python
* Type: Passive and Bruteforce.
* Api Keys added: 1 (VirusTotal).

It performs Passive scan and Bruteforce but not resolves what it found in passive. It does not stand out especially anywhere.

#### Pros

* Transfer zone check.
* CSV output customization.

#### Cons

* Python 2.
* Output is messy.
* Slow.

### [aiodnsbrute](https://github.com/blark/aiodnsbrute)

* Author: [blark](https://github.com/blark)
* Language: Python
* Type: Bruteforce.

According to its description is mainly focused in speed and also has with multiple output formats.

#### Pros

* Multiple output formats.
* Customizable DNS lookup query.
* Fast.

#### Cons

* Feels outdated and abandoned.

### [dmut](https://github.com/bp0lr/dmut)

* Author: [bp0lr](https://github.com/bp0lr)
* Language: Go
* Type: Alterations.

Fast permutations tool with very good wordlist.

#### Pros

* Fastest in its type.
* Lot of DNS options to optimize.

#### Cons

* Output is a bit poor.

### [subdomain3](https://github.com/yanxiu0614/subdomain3)

* Author: [yanxiu0614](https://github.com/yanxiu0614)
* Language: Python
* Type: Bruteforce.

Bruteforce tools with some interesting additions like IP, CDN or CIDR support.

#### Pros

* Fastest in its type.
* The IP, CDN and CIDR support
* Multi-level subdomains option.

#### Cons

* Python 2.
* Feels outdated and abandoned.
* In some cases, it missed some subdomains that the rest did.

### [Sudomy](https://github.com/Screetsec/Sudomy)

* Author: [Screetsec](https://github.com/Screetsec)
* Language: Python
* Type: Passive, Active and Bruteforce (Bruteforce with Gobuster, so not tested).
* Api Keys added: 9 (Shodan, Censys, VirusTotal, BinaryEdge, SecurityTrails, DnsDB, PassiveTotal, SpySe and Facebook).

Much more than a subdomain tool, it's a recon suite, but the subdomain search process is not delegated to third parties, so it gets on this list.

#### Pros

* Multiple options apart the subdomain search.
* Active scan really fast.

#### Cons

* No results not found by others.
* Active scans output could be better.

### [Findomain](https://github.com/Findomain/Findomain)

* Author: [Edu4rdSHL](https://github.com/Edu4rdSHL)
* Language: Rust
* Type: Passive, Active and bruteforce.
* Api Keys added: 4 (Facebook , Spyse, VirusTotal and SecurityTrails).

Findomain is one of the standard subdomain finder tools in the industry, it has a limited free version and a paid full-featured version.

#### Pros

* Really fast.
* Free version is still completely useful.

#### Cons

* Paid version has all the features.
* No customizable output file in free version.

## Results

### Passive

With amass and subfinder this part is more than completed, but there are other tools that, depending on the objective, may provide valuable information.

1. subfinder
2. amass
3. Findomain
4. Sudomy
5. sublist3r

### Active

In this field subfinder is the best, I find it to get results incredibly fast.

1. Findomain
2. subfinder
3. Sudomy
4. Amass

### Bruteforce

Again projectdiscovery does a great job with shuffledns and is far from the rest of the tools in speed and options.

1. shuffledns
2. Findomain
3. dnscan
4. gobuster
5. aiodnsbrute

### Alterations

I don't find alterations and permutations with resolution useful, but in case you like it, dmut should be your option by far.

1. dmut
2. altdns

## Final thoughts

When I started the review, I believed that amass would be the winner in most cases, but it seems that I have found new tools with which to improve the workflow, just as it happened with gobuster in the bruteforce section. In the permutations/alterations part I don't see the utility, they don't solve anything quickly and I think it is much more useful to use tools like [dnsgen](https://github.com/ProjectAnte/dnsgen) to generate a good wordlist of alterations and then run it with shuffledns, or any of the bruteforce tool to resolve them.

Finally, thanks to all the tools developers who facilitate our work and implement the recon methodology better and better.



