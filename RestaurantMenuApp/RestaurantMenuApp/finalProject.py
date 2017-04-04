from flask import Flask, flash,render_template, request, redirect, url_for, jsonify, session as login_session, make_response
app = Flask(__name__)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
import random, string, json, httplib2, requests
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

CLIENT_ID = json.loads(
	open('client_secrets.json','r').read())['web']['client_id']

engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create anti-forgery state token
@app.route('/')
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['user_id'] = gplus_id
	
    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
	
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output
	
# Create a user given a login session
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

# Get a user object given an ID
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

# Get a user object given the users email
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None	

#Disconnect google signin		
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: ' 
    print login_session['username']
    if access_token is None:
 	print 'Access Token is None'
    	response = make_response(json.dumps('Current user not connected.'), 401)
    	response.headers['Content-Type'] = 'application/json'
    	return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token'] 
    	del login_session['gplus_id']
    	del login_session['username']
    	del login_session['email']
    	del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        user = None
    	response = make_response(json.dumps('Successfully disconnected.'), 200)
    	response.headers['Content-Type'] = 'application/json'
    	return response
    else:
    	response = make_response(json.dumps('Failed to revoke token for given user.', 400))
    	response.headers['Content-Type'] = 'application/json'
    	return response

#Display the list of restaurants from the db to the user		
@app.route('/restaurants')
def restaurants():
	restaurants = session.query(Restaurant).all()	
	#Only show them the public page if they are not logged in
	if 'username' not in login_session:
		return render_template('publicrestaurants.html', restaurants=restaurants)
	else:
		user = getUserInfo(login_session['user_id'])
		return render_template(
		'restaurants.html', restaurants=restaurants, user=user)
		
#Allow the user to create a new restaurant
@app.route('/restaurants/new', methods=['GET', 'POST'])
def newRestaurant():
	if 'username' not in login_session:
		return redirect('/login')
	if request.method == 'POST':
		newItem = Restaurant(name=request.form['name'],user_id=login_session['user_id'])
		session.add(newItem)
		session.commit()
		flash('New Restaurant Created')
		return redirect(url_for('restaurants'))
	else:
		user = getUserInfo(login_session['user_id'])
		return render_template('newrestaurant.html',user=user)

@app.route('/restaurants/<int:restaurant_id>/edit', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
	if 'username' not in login_session:
		return redirect('/login')
	editedRestaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	creator = getUserInfo(editedRestaurant.user_id)
	user = getUserInfo(login_session['user_id'])
	if creator != user:
		flash('You can\'t edit restaurants created by other users!')
		return redirect(url_for('restaurants'))
	if request.method == 'POST':
		if request.form['name']:
			editedRestaurant.name = request.form['name']
			session.add(editedRestaurant)
			session.commit()
			flash('Restaurant Succesfully Edited')
			return redirect(url_for('restaurants'))
	else:
		return render_template('editrestaurant.html',restaurant_id=restaurant_id,editedRestaurant=editedRestaurant,user=user)

@app.route('/restaurants/<int:restaurant_id>/delete', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
	if 'username' not in login_session:
		return redirect('/login')
	restaurantToDelete = session.query(Restaurant).filter_by(id=restaurant_id).one()		
	creator = getUserInfo(restaurantToDelete.user_id)
	user = getUserInfo(login_session['user_id'])
	if creator != user:
		flash('You can\'t delete restaurants created by other users!')
		return redirect(url_for('restaurants'))
	if request.method == 'POST':
		session.delete(restaurantToDelete)
		session.commit()
		flash('Restaurant Succesfully Deleted')
		return redirect(url_for('restaurants'))

@app.route('/restaurants/<int:restaurant_id>/menu')
def restaurantMenu(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()	
	items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id)
	creator = getUserInfo(restaurant.user_id)
	if 'user_id' in login_session:
		user = getUserInfo(login_session['user_id'])
	else:
		user = None
	if 'username' not in login_session or user != creator:
		return render_template(
		'publicmenu.html', restaurant=restaurant, items=items, restaurant_id=restaurant_id,creator=creator)
	else:
		return render_template(
		'menu.html', restaurant=restaurant, items=items, restaurant_id=restaurant_id, user=user)

@app.route('/restaurants/<int:restaurant_id>/menuitem/new', methods = ['GET','POST'])
def newMenuItem(restaurant_id):
	if 'username' not in login_session:
		return redirect('/login')
	restaurant= session.query(Restaurant).filter_by(id=restaurant_id).one()		
	creator = getUserInfo(restaurant.user_id)
	user = getUserInfo(login_session['user_id'])
	if creator != user:
		flash('You can\'t create menu items for other users restaurants!')
		return redirect(url_for('restaurants'))
	if request.method == 'POST':
		restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
		newItem = MenuItem(name=request.form['name'], description=request.form[
						  'description'], price=request.form['price'], course=request.form['course'], restaurant_id=restaurant_id, user_id = restaurant.user_id)
		session.add(newItem)
		session.commit()
		flash('New Menu Item Created')
		return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
	else:
		user = getUserInfo(login_session['user_id'])
		return render_template('newmenuitem.html', restaurant_id=restaurant_id,user=user)

@app.route('/restaurants/<int:restaurant_id>/menuitem/<int:menu_id>/edit',
   methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
	if 'username' not in login_session:
		return redirect('/login')
	editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
	restaurant= session.query(Restaurant).filter_by(id=restaurant_id).one()		
	creator = getUserInfo(restaurant.user_id)
	user = getUserInfo(login_session['user_id'])
	if creator != user:
		flash('You can\'t edit menu items for other users restaurants!')
		return redirect(url_for('restaurants'))		
	if request.method == 'POST':
		if request.form['name']:
			editedItem.name = request.form['name']
		if request.form['description']:
			editedItem.description = request.form['description']
		if request.form['price']:
			editedItem.price = request.form['price']
		if request.form['course']:
			editedItem.course = request.form['course']
		session.add(editedItem)
		session.commit()
		flash('Menu Item Succesfully Edited')
		return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
	else:
		user = getUserInfo(login_session['user_id'])
		return render_template(
		'editmenuitem.html', restaurant_id=restaurant_id, menu_id=menu_id, item=editedItem,user=user)

@app.route('/restaurants/<int:restaurant_id>/menuitem/<int:menu_id>/delete',
   methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
	if 'username' not in login_session:
		return redirect('/login')
	itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
	restaurant= session.query(Restaurant).filter_by(id=restaurant_id).one()		
	creator = getUserInfo(restaurant.user_id)
	user = getUserInfo(login_session['user_id'])
	if creator != user:
		flash('You can\'t delete menu items for other users restaurants!')
		return redirect(url_for('restaurants'))			
	if request.method == 'POST':
		session.delete(itemToDelete)
		session.commit()
		flash('Menu Item Succesfully Deleted')
		return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))

#These are json endpoints that return an array with information about
#All the restaurants, a specific restaurant or a specific menu item
@app.route('/restaurants/JSON')
def restaurantsJSON():
	restaurants = session.query(Restaurant).all()
	return jsonify(Restaurants=[r.serialize for r in restaurants])

@app.route('/restaurants/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	items = session.query(MenuItem).filter_by(
	restaurant_id=restaurant_id).all()
	return jsonify(MenuItems=[i.serialize for i in items])

@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def restaurantMenuItemJSON(restaurant_id,menu_id):
	item = session.query(MenuItem).filter_by(id=menu_id).one()
	return jsonify(MenuItem=[item.serialize])
	
# Disconnect allow option to add more providers
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        flash("You have successfully been logged out.")
        return redirect(url_for('restaurants'))
    else:
        flash("You were not logged in")
        return redirect(url_for('restaurants'))
		
if __name__ == '__main__':
	app.debug = True
	app.secret_key = 'super secret key'
	app.config['SESSION_TYPE'] = 'filesystem'
	app.run(host='0.0.0.0', port=5000)