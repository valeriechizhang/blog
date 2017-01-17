# Blog

This is a python web application using Google App Engine. 

You can view a live demo here: https://blog-155822.appspot.com/

Features:
1. User registration and log in.
2. Create, edit, or delete his/her own blog posts.
3. Like and leave comments on existing blog posts.
4. User can edit or delete his/her own comments.
5. User doesn't need to log in again using the same browser, unless he/she chooses to log out.

Reference: Udacity Nanodegree Course in Full Stack Web Developer 

# How to run:
1. Install Google App Engine SDK: https://cloud.google.com/appengine/docs/php/download
2. Download the project.
3. In the project directory, run command:
      dev_appserver.py app.yaml
4. View the project at http://localhost:8080/ 
* Run this command if you wish to run the project on a different port
    dev_appserver.py app.yaml --port=[PORT_NUMBER] app.yaml 
  


