from flask import Flask, flash,render_template, request, redirect, url_for, jsonify, session as login_session, make_response
app = Flask(__name__)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem
import random, string, json, httplib2, requests
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

CLIENT_ID = json.loads(
	open('client_secrests.json','r').read())['web']['client_id']


engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

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

@app.route('/')
@app.route('/login')
def showLogin():
	state = ''.join(random.choice(string.ascii_uppercase + string.
		digits)for x in xrange(32))
	login_session['state'] = state
	return render_template('login.html')

@app.route('/login')
def gconnect():
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state parameter'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	code = request.data
	try:
		#Upgrade the authorization code into a credentials object
		oauth_flow = flow_from_clientsecrets('client_secrets.json',
			scope='')
		oauth_flow.redirect_uri = 'postmessage'
		credentials = oauth_flow.step2_exchange(code)
	except FlowExchangeError:
		response = make_response(json.dumps('Failed to upgrade the authorization code.'),401)
		response.headers['Content-Type'] = 'application/json'
		return response
	#Check that the access token is valid
	access_token = credentials.access_token
	url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
	h = httplib2.Http()
	result = json.loads(h.request(url,'GET'[1]))
	if result.get('error') is not None:
		response = make_response(json.dumps(result.get('error')), 500)
		response.headers['Content-Type'] = 'application/json'
	#Verify that the access token is used for the intended user
	gplus_id = credentials.id_token['sub']
	if result['user_id'] == gplus_id:
		response = make_response(
			json.dumps("Token's user ID doesn't match given user ID."),
			401)
		print "Token's client ID does not match app's."
		response.headers['Content-Type'] = 'application/json'
		return response
	stored_credentials = login_session.get('credentials')
	stored_gplus_id = login_session.get('gplus_id')
	if stored_credentials is not None and gplus_id == stored_gplus_id:
		response = make_response(json.dumps('Current user is already connected.'),200)
		response.headers['Content-Type'] = 'application/json'
	#Store the access token in the session for later use
	login_session['credentials'] = credentials
	login_session['gplus_id'] = gplus_id

	login_session['username'] = data["name"]
	login_session['picture'] = data["picture"]
	login_session['email'] = data["email"]

	#Get user info
	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = {'access_token': credentials.access_token, 'alt':'json'}
	answer = requests.get(userinfo_url,params=params)
	data = json.loads(answer.text)

@app.route('/restaurants')
def restaurants():
    restaurants = session.query(Restaurant).all()
    return render_template(
        'restaurants.html', restaurants=restaurants)

@app.route('/restaurants/new', methods=['GET', 'POST'])
def newRestaurant():
    if request.method == 'POST':
        newItem = Restaurant(name=request.form['name'])
        session.add(newItem)
        session.commit()
        flash('New Restaurant Created')
        return redirect(url_for('restaurants'))
    else:
        return render_template('newrestaurant.html')

@app.route('/restaurants/<int:restaurant_id>/edit', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
	editedRestaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	if request.method == 'POST':
		if request.form['name']:
			editedRestaurant.name = request.form['name']
			session.add(editedRestaurant)
			session.commit()
			flash('Restaurant Succesfully Edited')
			return redirect(url_for('restaurants'))
	else:
		return render_template('editrestaurant.html',restaurant_id=restaurant_id,editedRestaurant=editedRestaurant)

@app.route('/restaurants/<int:restaurant_id>/delete', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    restaurantToDelete = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        session.delete(restaurantToDelete)
        session.commit()
        flash('Restaurant Succesfully Deleted')
        return redirect(url_for('restaurants'))

@app.route('/restaurants/<int:restaurant_id>/menu')
def restaurantMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id)
    return render_template(
        'menu.html', restaurant=restaurant, items=items, restaurant_id=restaurant_id)

@app.route('/restaurants/<int:restaurant_id>/menuitem/new', methods = ['GET','POST'])
def newMenuItem(restaurant_id):
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'], description=request.form[
                          'description'], price=request.form['price'], course=request.form['course'], restaurant_id=restaurant_id)
        session.add(newItem)
        session.commit()
        flash('New Menu Item Created')
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id=restaurant_id)

@app.route('/restaurants/<int:restaurant_id>/menuitem/<int:menu_id>/edit',
           methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
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
        return render_template(
            'editmenuitem.html', restaurant_id=restaurant_id, menu_id=menu_id, item=editedItem)

@app.route('/restaurants/<int:restaurant_id>/menuitem/<int:menu_id>/delete',
           methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Succesfully Deleted')
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))

if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'
    app.run(host='0.0.0.0', port=5000)