var express     = require('express');
var app         = express();
var bodyParser  = require('body-parser');
var morgan      = require('morgan');
var mongoose    = require('mongoose');

var jwt    = require('jsonwebtoken');
var config = require('./config');
var User   = require('./app/models/user');

var port = process.env.PORT || 8080;
mongoose.connect(config.database);
app.set('secret_token', config.secret);

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(morgan('dev'));

var apiRoutes = express.Router(); 

apiRoutes.get('/users', function(req, res) {
  User.find({}, function(err, users) {
    res.json(users);
  });
});   

apiRoutes.post('/authenticate', function(req, res) {
  User.findOne({ name: req.body.name }, function(err, user) {
    if (err) throw err;

    if (!user) {
      res.json({ success: false, message: 'Authentication failed. User not found.' });
    } 
    else if (user) {
      if (user.password != req.body.password) {
        res.json({ success: false, message: 'Authentication failed. Wrong password.' });
      } 
      else {
        var token = jwt.sign(user, app.get('secret_token'), { expiresInMinutes: 1440 });

        res.json({ success: true, message: 'Authentication successfully', token: token });
      }   
    }
  });
});

apiRoutes.use(function(req, res, next) {
  var token = req.body.token || req.query.token || req.headers['x-access-token'];

  if (token) {
    jwt.verify(token, app.get('superSecret'), function(err, decoded) {      
      if (err) {
        return res.json({ success: false, message: 'Authentication failed. Wrong authentication token.' });    
      } 
      else {
        req.decoded = decoded;    
        next();
      }
    });
  } 
  else {
    return res.status(403).send({ success: false,  message: 'Authentication failed. No token provided.' });   
  }
});

app.use('/api', apiRoutes);
app.listen(port);
console.log('Magic happens at http://localhost:' + port);