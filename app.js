const express = require('express');
const exphbs = require('express-handlebars');
const fileUpload = require('express-fileupload');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const dotenv = require('dotenv');
const db = require('./db');

dotenv.config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());
app.use(express.static(path.join(__dirname, 'public')));

app.engine('handlebars', exphbs());
app.set('view engine', 'handlebars');

// Middleware para autenticar JWT
const authenticateJWT = (req, res, next) => {
  const token = req.cookies.token;

  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.redirect('/login');
  }
};

// Rutas
app.get('/', async (req, res) => {
  const result = await db.query('SELECT * FROM skaters');
  res.render('home', { participants: result.rows });
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await db.query('SELECT * FROM skaters WHERE email = $1', [email]);

  if (result.rows.length > 0) {
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      const token = jwt.sign({ email: user.email, nombre: user.nombre }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.cookie('token', token, { httpOnly: true });
      res.redirect('/');
    } else {
      res.render('login', { error: 'Contraseña incorrecta' });
    }
  } else {
    res.render('login', { error: 'Usuario no encontrado' });
  }
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { email, nombre, password, confirm_password, anos_experiencia, especialidad } = req.body;
  const foto = req.files.foto;

  if (password !== confirm_password) {
    return res.render('register', { error: 'Las contraseñas no coinciden' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const fotoPath = `/images/${foto.name}`;

  foto.mv(path.join(__dirname, 'public', 'images', foto.name), async err => {
    if (err) return res.status(500).send(err);

    await db.query(
      'INSERT INTO skaters (email, nombre, password, anos_experiencia, especialidad, foto, estado) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [email, nombre, hashedPassword, anos_experiencia, especialidad, fotoPath, false]
    );
    res.redirect('/login');
  });
});

app.get('/profile', authenticateJWT, async (req, res) => {
  const result = await db.query('SELECT * FROM skaters WHERE email = $1', [req.user.email]);
  res.render('profile', result.rows[0]);
});

app.post('/profile/update', authenticateJWT, async (req, res) => {
  const { nombre, password, confirm_password, anos_experiencia, especialidad } = req.body;

  if (password !== confirm_password) {
    return res.render('profile', { error: 'Las contraseñas no coinciden' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  await db.query(
    'UPDATE skaters SET nombre = $1, password = $2, anos_experiencia = $3, especialidad = $4 WHERE email = $5',
    [nombre, hashedPassword, anos_experiencia, especialidad, req.user.email]
  );

  res.redirect('/profile');
});

app.post('/profile/delete', authenticateJWT, async (req, res) => {
  await db.query('DELETE FROM skaters WHERE email = $1', [req.user.email]);
  res.clearCookie('token');
  res.redirect('/');
});

app.get('/admin', authenticateJWT, async (req, res) => {
  const result = await db.query('SELECT * FROM skaters');
  res.render('admin', { participants: result.rows });
});

app.post('/admin/update', authenticateJWT, async (req, res) => {
  const { id, estado } = req.body;
  await db.query('UPDATE skaters SET estado = $1 WHERE id = $2', [estado === 'on', id]);
  res.redirect('/admin');
});

app.listen(3000, () => {
  console.log('Servidor en ejecución en el puerto 3000');
});
