const express =  require('express');
const User = require('./user.model');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const router =  express.Router();

const JWT_SECRET = process.env.JWT_SECRET_KEY

router.post("/admin", async (req, res) => {
    const {username, password} = req.body;
    try {
        const admin =  await User.findOne({username});
        if(!admin || admin.role !== 'admin') {
            return res.status(401).json({message: "Invalid admin credentials."});
        }

        const passwordMatches = await bcrypt.compare(password, admin.password);
        if(!passwordMatches) {
            return res.status(401).json({message: "Invalid admin credentials."});
        }

        if(!JWT_SECRET) {
            return res.status(500).json({message: "JWT_SECRET_KEY is not configured."});
        }
        
        const token =  jwt.sign(
            {id: admin._id, username: admin.username, role: admin.role}, 
            JWT_SECRET,
            {expiresIn: "1h"}
        )

        return res.status(200).json({
            message: "Authentication successful",
            token: token,
            user: {
                username: admin.username,
                role: admin.role
            }
        })
        
    } catch (error) {
       console.error("Failed to login as admin", error)
         return res.status(500).json({message: "Failed to login as admin"});
    }
})

module.exports = router;