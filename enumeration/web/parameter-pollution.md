# HTTP Parameter pollution

```
# Inject existing extra parameters in GET:
https://www.bank.com/transfer?from=12345&to=67890&amount=5000&from=ABCDEF
https://www.site.com/sharer.php?u=https://site2.com/blog/introducing?&u=https://site3.com/test
```

![](<../../.gitbook/assets/image (17).png>)
