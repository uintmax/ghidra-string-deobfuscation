# Ghidra String Deobfuscation

Finds strings obfuscated by [github.com/adamyaxley/Obfuscate](https://github.com/adamyaxley/Obfuscate) and deobfuscates them.  
Check out the program in the `obfuscated-example` directory as an example target. Different compilers and optimization levels may require changes to the script.

## Example Output

```
StringDeobfuscator.java> Long string patterns found: 9
StringDeobfuscator.java> Short string patterns found: 5
StringDeobfuscator.java> Obfuscated string at 00101364
StringDeobfuscator.java> 	Key: d9 93 ef bb 19 cf e3 2d
StringDeobfuscator.java> 	Length: 10
StringDeobfuscator.java> 	Deobfuscated string: libc.so.6
StringDeobfuscator.java> Obfuscated string at 00101908
StringDeobfuscator.java> 	Key: e3 91 2d fd 25 09 7b 7b
StringDeobfuscator.java> 	Length: 14
StringDeobfuscator.java> 	Deobfuscated string: libnethttp.so
StringDeobfuscator.java> Obfuscated string at 00101a0c
StringDeobfuscator.java> 	Key: f1 43 39 ed 95 ff 2f cf
StringDeobfuscator.java> 	Length: 10
StringDeobfuscator.java> 	Deobfuscated string: send_file
StringDeobfuscator.java> Obfuscated string at 00101b78
StringDeobfuscator.java> 	Key: fd 4f f1 bd a3 7d 1f d3
StringDeobfuscator.java> 	Length: 33
StringDeobfuscator.java> 	Deobfuscated string: www.malicious.example/upload.php
...
```

## References

- [Ghidra documentation](https://ghidra.re/ghidra_docs/api/index.html)
- [Ghidra.re: Advanced development](https://ghidra.re/ghidra_docs/GhidraClass/AdvancedDevelopment/GhidraAdvancedDevelopment.html)