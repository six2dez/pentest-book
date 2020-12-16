# Files

### Common

```bash
# Check real file type
file file.xxx

# Analyze strings
strings file.xxx
strings -a -n 15 file.xxx # Check the entire file and outputs strings longer than 15 chars

# Check embedded files
binwalk file.xxx # Check
binwalk -e file.xxx # Extract

# Check as binary file in hex
ghex file.xxx

# Check metadata
exiftool file.xxx

# Stego tool for multiple formats
wget https://embeddedsw.net/zip/OpenPuff_release.zip
unzip OpenPuff_release.zip -d ./OpenPuff
wine OpenPuff/OpenPuff_release/OpenPuff.exe

# Compressed files
fcrackzip file.zip
# https://github.com/priyankvadaliya/Zip-Cracker-
python zipcracker.py -f testfile.zip -d passwords.txt
python zipcracker.py -f testfile.zip -d passwords.txt -o extractdir

# Office documents
https://github.com/assafmo/xioc

# Zip files in website
pip install remotezip
# list contents of a remote zip file
remotezip -l "http://site/bigfile.zip"
# extract file.txt from a remote zip file
remotezip "http://site/bigfile.zip" "file.txt"

# Grep inside any files
# https://github.com/phiresky/ripgrep-all
rga "whatever" folder/
```

### Disk files

```bash
# guestmount can mount any kind of disk file
sudo apt-get install libguestfs-tools
guestmount --add yourVirtualDisk.vhdx --inspector --ro /mnt/anydirectory
```

### Audio

```bash
# Check spectrogram
wget https://code.soundsoftware.ac.uk/attachments/download/2561/sonic-visualiser_4.0_amd64.deb
dpkg -i sonic-visualiser_4.0_amd64.deb

# Check for Stego
hideme stego.mp3 -f && cat output.txt #AudioStego
```

### Images

```bash
# Stego
wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
chmod +x stegsolve.jar
java -jar stegsolve.jar

# Stegpy
stegpy -p file.png

# Check png corrupted
pngcheck -v image.jpeg

# Check what kind of image is
identify -verbose image.jpeg

# Stegseek
# https://github.com/RickdeJager/stegseek
stegseek --seed file.jpg
stegseek file.jpg rockyou.txt 
```

