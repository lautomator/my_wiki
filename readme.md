# My Wiki

## Overview
This project was created as part of the requirements for the Udacity Web Development course. I highly recommend this course to anyone interested in learning about using Google App engine, Python, database, and caching. There was, of course, much more coverred in the course. Check out the [Udacity Web Development Course](https://www.udacity.com/course/web-development--cs253).

## Setup
To set this up, you will need to:
* install Google App Engine on your local machine. The instructions are [here](https://cloud.google.com/docs/)
* install [virtualenv](http://docs.python-guide.org/en/latest/dev/virtualenvs/)
* you may also need to install [PIP](https://en.wikipedia.org/wiki/Pip_(package_manager))
* Download this repo
* `cd` to the project folder `my_wiki/`
* create an `env` directory: `virtualenv env`
* activate the environment: `source env/bin/activate`
* get the requirments for this project installed: `pip install -r requirements.txt`
* run the appserver: `dev_appserver.py ../my_wiki` (You may need to be the root user)

## Technical
The site is authored using Webapp2 (google app engine).
See the `requirements.txt` for **virtualenv** specs.

## Deployment
View the app [here](http://t-decoder-840.appspot.com/).
