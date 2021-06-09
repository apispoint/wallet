# AP Wallet 

This utility provides the cryptographic requirements needed to
establish BTC offline deep cold storage or paper wallets.

The software is written to use Bouncy Castle's FIPS validated
cryptographic module. You must download the jar file from Bouncy
Castle. The library is not included in this repo. 


Offline usage is recommended for security reasons. Be warned offline
cold storage is dangerous and your BTC can be lost or stolen if the
private key is lost or compromised.

# Output

```
[ok] FIPS ready
[ok] key_provider=BCFIPS version 1.000201
[ok] rng_provider=BCFIPS version 1.000201
[ok] sha_provider=BCFIPS version 1.000201
[ok] rmd_provider=BCFIPS version 1.000201

BTC
s[64]: b06c...OMITTED...53cd
  wif: L38f...OMITTED...RjBU
  adr: 17XQ...OMITTED...ESC4
```
```
Where: s[64] = Hexadecimal private key
         wif = Wallet Import Format
         adr = BTC Address
```
# License

*AP Wallet* is released under The MIT License.
