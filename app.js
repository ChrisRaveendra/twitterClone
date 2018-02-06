var express = require('express');
var session = require('express-session')
var path = require('path');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var passport = require('passport');
var LocalStrategy = require('passport-local');
var models = require('./models/models')
var routes = require('./routes/index');
var auth = require('./routes/auth');
var MongoStore = require('connect-mongo')(session);
var mongoose = require('mongoose');
var app = express();

var crypto = require('crypto');
var User = require('./models/models.js').User;

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

//MONGO DB setup
mongoose.connection.on('connected', function () {
	console.log('Connected to MongoDb!')
});

mongoose.connect(process.env.MONGODB_URI);

// Passport stuff here

// Session info here
function hashPassword(password) {
	var hash = crypto.createHash('sha256');
	hash.update(password);
	return hash.digest('hex');
}

app.use(session({
	secret: 'test',
	store: new MongoStore({ mongooseConnection: mongoose.connection })
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Passport Serialize
passport.serializeUser(function (user, cb) {
	cb(null, user._id);
});

// Passport Deserialize
passport.deserializeUser(function(id, cb) {
	User.findById(id, function(err, user) {
		cb(null,user);
	});
});

// Passport Strategy
passport.use(new LocalStrategy(
	function (email, password, cb) {
		//search for user by email & if successful, compare hashed password
		User.findOne({ email: email }, function (err, user) {
			// console.log(user);
			if (err || !user) cb(null, false);
			else if (hashPassword(password) === user.password) {
				cb(null, user);
			}
			else cb(null, false);
		})
	}
));


app.use('/', auth(passport));
app.use('/', routes);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
	var err = new Error('Not Found');
	err.status = 404;
	next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
	app.use(function(err, req, res, next) {
		res.status(err.status || 500);
		res.render('error', {
			message: err.message,
			error: err
		});
	});
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
	res.status(err.status || 500);
	res.render('error', {
		message: err.message,
		error: {}
	});
});

app.listen(3000);

module.exports = app;
