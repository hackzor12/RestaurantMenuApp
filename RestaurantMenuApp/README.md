# RestaurantMenuApp
A Flask application that displays restaurants and their menus

To get started:
1. Install VirtualBox (https://www.virtualbox.org/wiki/Downloads)
2. Install Vagrant (https://www.vagrantup.com/)
3. Clone this Repo (git clone https://github.com/hackzor12/RestaurantMenuApp.git)
4. Navigate to the RestaurantMenuApp folder (cd /RestaurantMenuApp)
5. Run python finalproject.py
6. Open http://localhost:5000/

Troubleshooting:

You may need to install the oauth2client package with pip. 
Setup tools may be broken due to this bug: https://bugs.launchpad.net/ubuntu/+source/python-pip/+bug/1658844

If it is broken then run these commands:
1. python -m pip install -U pip
2. pip install -U pip setuptools

Ensure that your Flask version is correct: 
1. pip install werkzeug==0.8.3
2. pip install flask==0.9
3. pip install Flask-Login==0.1.3


