# SI 364 - Final Project questions

## Overall

* **What's a one-two sentence description of what your app will do?**
The user will enter a Point of Interest whch will go to google geocode api returning lat, long.  Then goes to yelp which returns suggested restuarants within in a mile.  This emailed to the user

## The Data

* **What data will your app use? From where will you get it? (e.g. scraping a site? what site? -- careful not to run it too much. An API? Which API?)**
Geocode API - given a POI return lat long
Yelp API - given lat long returns restaurants

* **What data will a user need to enter into a form?**
POI (potentially type of restaurant)

* **How many fields will your form have? What's an example of some data user might enter into it?**
Form for the POI, form the username/email, potentially type of restaurant

* **After a user enters data into the form, what happens? Does that data help a user search for more data? Does that data get saved in a database? Does that determine what already-saved data the user should see?**
The POI and lat long will be save in one db
Save the username and email in another db
Search db that has the username with POI's they have searched
Lat/Long with the top 5 restaurants within a mile

* **What models will you have in your application?**
User, POI, Search, Restaurants

* **What fields will each model have?**
User - User_ID, email, username
POI- POI_ID, POI, lat, long
Search- User_ID, POI_ID
Restaurant- POI_ID, Rest_ID, Restuarant Name

* **What uniqueness constraints will there be on each table? (e.g. can't add a song with the same title as an existing song)**
Can not have two users with the same email or username
Wouldnt want same POI to be saved multiple times
Will only show the most recent search for given POI

* **What relationships will exist between the tables? What's a 1:many relationship between? What about a many:many relationship?**
User-Search: 1 to many
POI-Search: many to many
POI-Restaurant: many to many

* **How many get_or_create functions will you need? In what order will you invoke them? Which one will need to invoke at least one of the others?**
1st for the users
2nd for the POI
3rd restaurants for the POI

POI will invoke the restaurant. 

## The Pages

* **How many pages (routes) will your application have?**
4

* **How many different views will a user be able to see, NOT counting errors?**
4

* **Basically, what will a user see on each page / at each route? Will it change depending on something else -- e.g. they see a form if they haven't submitted anything, but they see a list of things if they have?**
/ - submit buttons for username, email, POI, type of restaurant. 
/results - Shows top restaurants after search
/map - list of Basketball Stadium for an idea of what to search
/history - the usernames past POI searches

## Extras

* **Why might your application send email?**
It will send an emailt to user after the search with restaurant feedback

* **If you plan to have user accounts, what information will be specific to a user account? What can you only see if you're logged in? What will you see if you're not logged in -- anything?**
User_ID will be specific to the user account
You can only see your history if you are logged in

* **What are your biggest concerns about the process of building this application?**
History aspect and database tables
