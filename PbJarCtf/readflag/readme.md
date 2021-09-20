# Readme 2/3 - Ethereum smart contract challenge

This was a very beginner friendly smart contract challenge. I solved 2 in a not intended way, which let me to use the same 
procedure for both readflag2 **and** readflag3.

I first went to https://ropsten.etherscan.io/ and then searched for the provided block and found the smart contract I was looking for. Then I copied the hex string into python and did the following:

```python3
b = a.fromhex("<long hex string>")
print(b)
```
And I saw the flag at the end of the string. 
You could have also first written it to a file and then call strings on it, but It gives you the flag either way!