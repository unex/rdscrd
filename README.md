```bash
sudo apt install apache2 python3.8 python3.8-dev python3-pip

sudo python3.8 -m pip install mod-wsgi
sudo mod_wsgi-express module-config > /etc/apache2/mods-available/wsgi.load
sudo a2enmod wsgi

cd /var/www/

sudo git clone https://github.com/notderw/rdscrd.git
cd rdscrd
sudo chown -R www-data:www-data .
sudo cp reddiscord.conf /etc/apache2/sites-available
sudo a2ensite reddiscord.conf

cp .env.example .env
vim .env

sudo systemctl restart nginx

export PIPENV_VENV_IN_PROJECT=1
pipenv install
```
