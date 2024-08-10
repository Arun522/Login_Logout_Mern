import React, { useState, useEffect } from 'react';
import axios from 'axios';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [foods, setFoods] = useState([]);
  const [newFood, setNewFood] = useState('');
  const [newFoodDate, setNewFoodDate] = useState('');

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      setIsLoggedIn(true);
      fetchFoods();
    }
  }, []);

  const fetchFoods = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:3001/api/foods', {
        headers: { 'Authorization': token }
      });
      setFoods(response.data);
    } catch (error) {
      console.error('Error fetching foods:', error);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      await axios.post('http://localhost:3001/api/register', { username, password });
      alert('User registered successfully');
    } catch (error) {
      alert('Error registering user');
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:3001/api/login', { username, password });
      localStorage.setItem('token', response.data.token);
      setIsLoggedIn(true);
      fetchFoods();
    } catch (error) {
      alert('Error logging in');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setIsLoggedIn(false);
    setFoods([]);
  };

  const handleAddFood = async (e) => {
    e.preventDefault();
    try {
      const token = localStorage.getItem('token');
      await axios.post('http://localhost:3001/api/foods', 
        { name: newFood, lastEatenDate: newFoodDate }, 
        { headers: { 'Authorization': token } }
      );
      setNewFood('');
      setNewFoodDate('');
      fetchFoods();
    } catch (error) {
      alert('Error adding food');
    }
  };

  const handleEatenFood = async (id) => {
    try {
      const token = localStorage.getItem('token');
      const date = prompt("Enter the date you ate this food (YYYY-MM-DD):");
      if (date) {
        await axios.put(`http://localhost:3001/api/foods/${id}`, 
          { lastEatenDate: date },
          { headers: { 'Authorization': token } }
        );
        fetchFoods();
      }
    } catch (error) {
      alert('Error updating food');
    }
  };

  const getDaysSinceEaten = (date) => {
    const diff = new Date() - new Date(date);
    return Math.floor(diff / (1000 * 60 * 60 * 24));
  };

  if (isLoggedIn) {
    return (
      <div>
        <h1>Food Tracker</h1>
        <button onClick={handleLogout}>Logout</button>
        
        <h2>Add New Food</h2>
        <form onSubmit={handleAddFood}>
          <input
            type="text"
            value={newFood}
            onChange={(e) => setNewFood(e.target.value)}
            placeholder="Enter food name"
            required
          />
          <input
            type="date"
            value={newFoodDate}
            onChange={(e) => setNewFoodDate(e.target.value)}
            required
          />
          <button type="submit">Add Food</button>
        </form>
        
        <h2>Your Foods</h2>
        <ul>
          {foods.map((food) => (
            <li key={food._id}>
              {food.name} - Last eaten {getDaysSinceEaten(food.lastEatenDate)} days ago
              <button onClick={() => handleEatenFood(food._id)}>Update Last Eaten Date</button>
            </li>
          ))}
        </ul>
      </div>
    );
  }

  return (
    <div>
      <h1>Food Tracker</h1>
      <form onSubmit={handleLogin}>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <button type="submit">Login</button>
      </form>
      <button onClick={handleRegister}>Register</button>
    </div>
  );
}

export default App;