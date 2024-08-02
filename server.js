const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const { Strategy: JWTStrategy, ExtractJwt } = require('passport-jwt');
const { createClient } = require('@supabase/supabase-js');
const fileUpload = require('express-fileupload');

dotenv.config();
const app = express();

// Supabase client setup
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);


app.use(fileUpload());
//basic one
//app.use(cors());

//eventual method
const corsOptions = {
    origin: 'http://localhost:5173', // replace with your frontend URL
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  };

  app.use(cors(corsOptions));

app.use(express.json());


app.use(passport.initialize());
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    console.log('Request Body:', req.body);
    next();
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Middleware for handling async functions
const asyncHandler = fn => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

// Passport JWT strategy setup
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET,
};

passport.use(new JWTStrategy(jwtOptions, async (jwtPayload, done) => {
    try {
        const { data: user, error } = await supabase
            .from('useraccount')
            .select('*')
            .eq('id', jwtPayload.userId)
            .single();

        if (error) {
            return done(error, false);
        }

        if (user) {
            return done(null, user);
        } else {
            return done(null, false);
        }
    } catch (error) {
        return done(error, false);
    }
}));

// Function to generate JWT token
const generateToken = (user) => {
    return jwt.sign(
        { userId: user.id, username: user.username, email: user.email, admin: user.admin },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );
};

// Route for user registration
app.post('/register', asyncHandler(async (req, res) => {
    const { username, email, password, admin } = req.body;

    try {
        // Check if a user with the same email already exists
        const { data: existingUsers, error: existingError } = await supabase
            .from('useraccount')
            .select('email')
            .eq('email', email);

        if (existingError) {
            console.error('Supabase error checking existing user:', existingError.message);
            return res.status(500).json({ error: 'Error checking existing user' });
        }

        if (existingUsers.length > 0) {
            return res.status(400).json({ error: 'User with this email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user into Supabase
        const { error } = await supabase.from('useraccount').insert([
            { username, email, password: hashedPassword, admin: admin ? 1 : 0 },
        ]);

        if (error) {
            console.error('Supabase insert error:', error.message);
            return res.status(500).json({ error: 'Error creating the user account' });
        }

        // Fetch newly registered user data
        const { data: newUser } = await supabase
            .from('useraccount')
            .select('*')
            .eq('email', email)
            .single();

        if (!newUser) {
            return res.status(404).json({ error: 'User not found after registration' });
        }

        // Generate JWT token
        const token = generateToken(newUser);

        // Return token and user data
        res.status(201).json({ token, user: newUser });


    } catch (error) {
        console.error('Error during registration:', error.message);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
}));

// Login endpoint
app.post('/login', asyncHandler(async (req, res) => {
    const { username, password } = req.body;

    try {
        // Fetch user from Supabase
        const { data: users, error } = await supabase
            .from('useraccount')
            .select('*')
            .eq('username', username);

        if (error) throw error;

        if (users.length === 0) {
            console.log('User not found');
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const user = users[0];

        // Compare the password with the hashed password stored in the database
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            console.log('Invalid password');
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Generate JWT token
        const token = generateToken(user);

        console.log('Login successful');
        res.status(200).json({ token, user });

    } catch (error) {
        console.error('Error during login:', error.message);
        res.status(400).json({ message: error.message });
    }
}));




// Route to add a game into the GameInfo database
app.post('/add-game-to-database', asyncHandler(async (req, res) => {
    const { Name, Console } = req.body;

    try {
        console.log('Received request to add game:', { Name, Console });

        const { data: existingGames, error: existingError } = await supabase
            .from('gameinfo')
            .select('gameid')
            .eq('name', Name)
            .eq('console', Console);

        if (existingError) {
            console.error('Supabase error checking existing game:', existingError.message);
            return res.status(500).json({ error: 'Error checking existing game', details: existingError.message });
        }

        if (existingGames.length > 0) {
            return res.status(420).json({ error: "A game with the same name and console already exists." });
        }

        if (req.files && req.files.CoverArt) {
            const coverArtFile = req.files.CoverArt;
            const coverArtBuffer = coverArtFile.data;
            const coverArtBase64 = coverArtBuffer.toString('base64'); // Convert to base64 string

            const { data: insertData, error: insertError } = await supabase.from('gameinfo').insert([
                { name: Name, coverart: coverArtBase64, console: Console } // Save base64 string
            ]);

            if (insertError) {
                console.error('Supabase insert error:', insertError.message);
                return res.status(500).json({ error: 'Error adding game to the database', details: insertError.message });
            } else {
                res.status(200).json({ message: "Game added successfully" });
            }
        } else {
            res.status(400).json({ error: "CoverArt is required." });
        }
    } catch (error) {
        console.error('Error adding game to the database:', error.message);
        res.status(500).json({ error: "Server error: " + error.message });
    }
}));






// Route for searching games based on a query
app.get('/api/search', asyncHandler(async (req, res) => {
    const searchQuery = req.query.q;

    if (!searchQuery) {
        return res.status(400).json({ error: 'Search query is required.' });
    }

    try {
        const results = await searchGames(searchQuery);
        res.json({ results });
    } catch (error) {
        console.error('Error searching games:', error.message);
        res.status(500).json({ error: 'Error searching games.' });
    }
}));

// Function to search games based on a query using Supabase
async function searchGames(searchTerm) {
    try {
        const { data, error } = await supabase
            .from('gameinfo')
            .select('gameid, name, coverart, console')
            .ilike('name', `%${searchTerm}%`);

        if (error) {
            throw new Error('Error searching games: ' + error.message);
        }

        const results = data.map(game => {
            let coverArtBase64 = game.coverart;
            return {
                GameId: game.gameid,
                Name: game.name,
                CoverArt: coverArtBase64,
                Console: game.console,
            };
        });

        return results;
    } catch (error) {
        console.error('Error searching games:', error);
        throw error;
    }
}







// Add wishlist game to wishlist
app.post('/api/add-to-wishlist/:userId/:gameId', asyncHandler(async (req, res) => {
    const { userId, gameId } = req.params;

    if (userId && gameId) {
        try {
            // Check if the game is already in the user's wishlist
            const { data: existingWishlist, error: checkError } = await supabase
                .from('vgwishlist')
                .select('wishlistid')
                .eq('userid', userId)
                .eq('gameid', gameId);

            if (checkError) throw checkError;

            if (existingWishlist.length > 0) {
                // The game is already in the user's wishlist
                return res.status(400).json({ error: "The game is already in your wishlist." });
            }

            // If the game is not in the wishlist, add it
            const { error: insertError } = await supabase
                .from('vgwishlist')
                .insert([{ userid: userId, gameid: gameId }]);

            if (insertError) throw insertError;

            res.status(200).json({ message: 'Game added to wishlist successfully' });

        } catch (error) {
            console.error('Error adding to wishlist:', error.message);
            res.status(500).json({ error: 'Error adding game to wishlist.' });
        }
    } else {
        res.status(400).json({ error: 'Invalid userId or gameId.' });
    }
}));



// Route to retrieve wishlist items for MyWishlist page
app.get('/api/mywishlist/:userId', asyncHandler(async (req, res) => {
    const userId = req.params.userId;
    try {
        const results = await getWishlistItems(userId);
        res.json({ results });
    } catch (error) {
        console.error('Error fetching wishlist items:', error.message);
        res.status(500).json({ error: 'Error fetching wishlist items.' });
    }
}));

// Function to retrieve wishlist items for a user
async function getWishlistItems(userId) {
    const { data, error } = await supabase
        .from('vgwishlist')
        .select(`
            gameinfo:gameid (
                gameid,
                name,
                coverart,
                console
            )
        `)
        .eq('userid', userId);

    if (error) throw error;

    return data.map(wishlistItem => {
        const game = wishlistItem.gameinfo;
        return {
            GameId: game.gameid,
            Name: game.name,
            CoverArt: game.coverart,
            Console: game.console,
        };
    });
}


// Remove wishlist game from wishlist
app.delete('/api/removewishlist/:userId/:gameId', asyncHandler(async (req, res) => {
    const { userId, gameId } = req.params;

    try {
        console.log(`Attempting to remove game with ID ${gameId} from wishlist of user with ID ${userId}`);

        // Fetch the game first to see if it exists
        const { data: existingGame, error: fetchError } = await supabase
            .from('vgwishlist')
            .select()
            .eq('userid', userId)
            .eq('gameid', gameId);

        if (fetchError) {
            console.error('Error fetching game:', fetchError.message);
            return res.status(500).json({ error: 'Error fetching game' });
        }

        console.log('Fetched game:', existingGame);

        if (!existingGame || existingGame.length === 0) {
            console.log(`Game with ID ${gameId} not found in the wishlist of user with ID ${userId}`);
            return res.status(404).json({ error: 'Game not found in the wishlist' });
        }

        // Remove the game from VGWishlist
        const { data: removedGame, error: removeError } = await supabase
            .from('vgwishlist')
            .delete()
            .eq('userid', userId)
            .eq('gameid', gameId);

        if (removeError) {
            console.error('Error in remove operation:', removeError.message);
            return res.status(500).json({ error: 'Error removing game from wishlist' });
        }

        console.log('Removed game:', removedGame);

        if (removedGame == null) {
            res.status(200).json({ message: 'Game removed successfully' });
        } else {
            console.log(`Game with ID ${gameId} not found in the wishlist of user with ID ${userId}`);
            res.status(404).json({ error: 'Game not found in the wishlist' });
        }
    } catch (error) {
        console.error('Error removing game from wishlist:', error.message);
        res.status(500).json({ error: 'Error removing game from wishlist' });
    }
}));










// Route to retrieve collection items for MyCollection page
app.get('/api/mycollection/:userId', asyncHandler(async (req, res) => {
    const userId = req.params.userId;
    try {
        const results = await getCollectionItems(userId);
        // Convert CoverArt to Base64
        results.forEach(game => game.CoverArt = game.CoverArt ? game.CoverArt.toString('base64') : null);
        res.json({ results });
    } catch (error) {
        console.error('Error fetching collection items:', error.message);
        res.status(500).json({ error: 'Error fetching collection items.' });
    }
}));

// Function to retrieve collection items for a user
async function getCollectionItems(userId) {
    const { data, error } = await supabase
        .from('vgcollection')
        .select('gameinfo(gameid, name, coverArt, console)')
        .eq('userid', userId);

    if (error) {
        console.error('Error fetching collection items:', error.message);
        throw error;
    }

    return data.map(item => ({
        GameId: item.GameInfo.GameId,
        Name: item.GameInfo.Name,
        CoverArt: item.GameInfo.CoverArt ? item.GameInfo.CoverArt.toString('base64') : null,
        Console: item.GameInfo.Console,
    }));
}

// Navigation from Search to check if the game details already exist for the game in collection
app.get('/api/check-gamedetails/:userId/:gameId', asyncHandler(async (req, res) => {
    const { userId, gameId } = req.params;

    try {
        const result = await checkGameDetails(userId, gameId);

        console.log('Result: ', result);

        res.json({ hasDetails: result });
    } catch (error) {
        console.error('Error checking GameDetails:', error.message);
        res.status(500).json({ error: 'Error checking GameDetails.' });
    }
}));

// Function to check if game details exist for a game in the collection
async function checkGameDetails(userId, gameId) {
    const { data, error } = await supabase
        .from('vgcollection')
        .select('gamedetailsid')
        .eq('userid', userId)
        .eq('gameid', gameId)
        .not('gamedetailsid', 'is', null);

    if (error) {
        console.error('Error checking game details:', error.message);
        throw error;
    }

    return data.length > 0;
}

// Giving GameInfo to the GameDetails page for details addition
app.get('/api/game-info/:gameId', asyncHandler(async (req, res) => {
    const gameId = req.params.gameId;

    try {
        // Fetch game details based on gameId
        const gameDetails = await getGameDetails(gameId);

        if (gameDetails) {
            // Directly use the stored Base64 string
            console.log('Game Details result: ', gameDetails);
            res.json({ gameDetails });
        } else {
            res.status(404).json({ error: 'Game not found' });
        }
    } catch (error) {
        console.error('Error fetching game details:', error.message);
        res.status(500).json({ error: 'Error fetching game details.' });
    }
}));


// Function to get game details by gameId
async function getGameDetails(gameId) {
    const { data, error } = await supabase
        .from('gameinfo')
        .select('gameid, name, coverart, console')
        .eq('gameid', gameId)
        .single();

    if (error) {
        console.error('Error fetching game details:', error.message);
        throw error;
    }

    return data;
}

// Adding Game Details + Game VGCollection Record
app.post('/api/add-game-details/:userId/:gameId', asyncHandler(async (req, res) => {
    const { userId, gameId } = req.params;
    const gameDetails = req.body;

    try {
        // Add game details
        const result = await addGameDetails(userId, gameId, gameDetails);

        if (result) {
            res.status(200).json({ message: 'Game details added successfully!' });
        } else {
            res.status(500).json({ error: 'Error adding game details.' });
        }
    } catch (error) {
        console.error('Error adding game details:', error.message);
        res.status(500).json({ error: `Error adding game details: ${error.message}` });
    }
}));

// Function to add game details to a game in the collection
async function addGameDetails(userId, gameId, gameDetails) {
    const { ownership, included, checkboxes, notes, completion, review, spoiler, price, rating } = gameDetails.gameDetails;

    // Assuming 'checkboxes' is an array of checkbox values, convert to a string
    const checkboxesString = Array.isArray(checkboxes) ? checkboxes.join(',') : checkboxes;

    const { data: gameDetailsData, error: gameDetailsError } = await supabase
        .from('GameDetails')
        .insert({
            Ownership: ownership,
            Included: included,
            Condition: checkboxesString,
            Notes: notes,
            Completion: completion,
            Review: review,
            Spoiler: spoiler,
            Price: price,
            Rating: rating
        })
        .select('gamedetailsid')
        .single();

    if (gameDetailsError) {
        console.error('Error adding game details:', gameDetailsError.message);
        throw gameDetailsError;
    }

    const { GameDetailsId } = gameDetailsData;

    const { data: vgCollectionData, error: vgCollectionError } = await supabase
        .from('vgcollection')
        .insert({
            UserId: userId,
            GameId: gameId,
            GameDetailsId: gamedetailsid
        });

    if (vgCollectionError) {
        console.error('Error adding VGCollection record:', vgCollectionError.message);
        throw vgCollectionError;
    }

    return vgCollectionData.length > 0;
}









// Remove a game from the collection
app.delete('/api/removecollection/:userId/:gameId', asyncHandler(async (req, res) => {
    const userId = req.params.userId;
    const gameId = req.params.gameId;

    try {
        // Check if the game is in the user's collection
        const { data: collectionData, error: collectionError } = await supabase
            .from('vgcollection')
            .select('vgcollectionId, gamedetailsid')
            .eq('userid', userId)
            .eq('gameid', gameId)
            .single();

        if (collectionError) {
            console.error('Error fetching collection data:', collectionError.message);
            return res.status(500).json({ error: 'Error fetching collection data' });
        }

        if (collectionData) {
            const vgCollectionId = collectionData.VGCollectionId;
            const gameDetailsId = collectionData.GameDetailsId;

            // Remove the game from VGCollection
            await removeGameFromCollection(userId, gameId);

            // Remove the associated GameDetails record
            await removeGameDetails(gameDetailsId);

            res.status(200).json({ message: 'Game removed successfully' });
        } else {
            res.status(404).json({ error: 'Game not found in the collection' });
        }
    } catch (error) {
        console.error('Error removing game from collection:', error.message);
        res.status(500).json({ error: 'Error removing game from collection' });
    }
}));

// Function to remove a game from the collection
async function removeGameFromCollection(userId, gameId) {
    const { error } = await supabase
        .from('vgcollection')
        .delete()
        .eq('userid', userId)
        .eq('gameid', gameId);

    if (error) {
        console.error('Error removing game from collection:', error.message);
        throw error;
    }
}

// Function to remove a GameDetails record
async function removeGameDetails(gameDetailsId) {
    const { error } = await supabase
        .from('gamedetails')
        .delete()
        .eq('gamedetailsid', gameDetailsId);

    if (error) {
        console.error('Error removing game details:', error.message);
        throw error;
    }
}














// Protected route example (use this structure for a "protected route")
app.get('/profiles', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
    console.log('Profiles request received');
    const { data, error } = await supabase.from('useraccount').select('*');
    if (error) {
        console.error('Error fetching profiles:', error.message);
        return res.status(400).json({ error });
    }
    console.log('Profiles fetched successfully:', data);
    res.json(data);
}));
