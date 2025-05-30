const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const cookieParser = require('cookie-parser');
const { Strategy: JWTStrategy, ExtractJwt } = require('passport-jwt');
const { createClient } = require('@supabase/supabase-js');
const fileUpload = require('express-fileupload');

dotenv.config();
const app = express();

// Supabase client setup
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);


// Middleware
app.use(fileUpload());
app.use(cookieParser());

const allowedOrigins = [
    'http://localhost:5173',                // dev
    'https://cdd-frontend.vercel.app'       // prod
];

const corsOptions = {
    origin: (incomingOrigin, callback) => {
        // incomingOrigin will be undefined for server-to-server or Postman
        if (!incomingOrigin || allowedOrigins.includes(incomingOrigin)) {
            callback(null, true);
        } else {
            callback(new Error(`CORS origin ${incomingOrigin} not allowed`));
        }
    },
    credentials: true,   // so cookies are accepted
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(passport.initialize());

// Logger for debugging
// app.use((req, res, next) => {
//     console.log(`${req.method} ${req.url}`);
//     console.log('Headers:', req.headers);
//     console.log('Cookies:', req.cookies);
//     next();
// });

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Async handler
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Passport JWT strategy
passport.use(new JWTStrategy({
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET,
}, async (payload, done) => {
    try {
        const { data: user, error } = await supabase
            .from('useraccount')
            .select('*')
            .eq('userid', payload.userId)
            .single();

        if (error) return done(error, false);
        return user ? done(null, user) : done(null, false);
    } catch (err) {
        done(err, false);
    }
}));

// Generate tokens
const generateAccessToken = user => jwt.sign(
    { userId: user.userid, username: user.username, admin: user.admin },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
);

const generateRefreshToken = user => jwt.sign(
    { userId: user.userid },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '30d' }
);

// Refresh token endpoint
app.post('/api/token/refresh', asyncHandler(async (req, res) => {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ error: 'No refresh token provided.' });

    try {
        const { userId } = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
        const { data: user, error } = await supabase
            .from('useraccount')
            .select('*')
            .eq('userid', userId)
            .single();
        if (error || !user) throw error || new Error('User not found');

        const newAccessToken = generateAccessToken(user);
        res.json({ accessToken: newAccessToken });
    } catch (err) {
        console.error('Refresh error:', err.message);
        res.status(403).json({ error: 'Invalid or expired refresh token.' });
    }
}));

// Registration
app.post('/register', asyncHandler(async (req, res) => {
    const { username, email, password, admin } = req.body;
    // check existing user
    const { data: existing, error: existErr } = await supabase
        .from('useraccount')
        .select('email')
        .eq('email', email);
    if (existErr) throw existErr;
    if (existing.length) return res.status(400).json({ error: 'Email in use.' });

    const hashed = await bcrypt.hash(password, 10);
    await supabase.from('useraccount').insert([{ username, email, password: hashed, admin: admin ? 1 : 0 }]);
    const { data: newUser } = await supabase.from('useraccount').select('*').eq('email', email).single();

    const accessToken = generateAccessToken(newUser);
    const refreshToken = generateRefreshToken(newUser);

    // Set HttpOnly cookie
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,           // MUST be true for SameSite=None
        sameSite: 'None',       // ← allow cross-site
        path: '/',
    });


    const safeUser = { userid: newUser.userid, username: newUser.username, email: newUser.email, admin: newUser.admin };
    res.status(201).json({ accessToken, user: safeUser });
}));

// Login
app.post('/login', asyncHandler(async (req, res) => {
    const { username, password } = req.body;
    const { data: users } = await supabase.from('useraccount').select('*').eq('username', username);
    const user = users[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,           // MUST be true for SameSite=None
        sameSite: 'None',       // ← allow cross-site
        path: '/',
    });


    const safeUser = { userid: user.userid, username: user.username, email: user.email, admin: user.admin };
    res.json({ accessToken, user: safeUser });
}));


// Protected example
app.get('/protected', passport.authenticate('jwt', { session: false }), (req, res) => {
    res.json({ message: 'Secure data', user: req.user });
});


// Get current user profile
app.get(
    '/api/me',
    passport.authenticate('jwt', { session: false }),
    (req, res) => {
        const { userid, username, email, admin } = req.user;
        res.json({ user: { userid, username, email, admin } });
    }
);


app.post('/api/logout', (req, res) => {
    // 1) clear the old one
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'Strict' : 'Lax',
        path: '/',            // must match the set path
    });

    res.json({ message: 'Logged out' });
});









// Route to add a game into the GameInfo database
app.post('/add-game-to-database', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
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
app.get(
    '/api/search',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const searchQuery = req.query.q;

        if (!searchQuery) {
            return res.status(400).json({ error: 'Search query is required.' });
        }

        try {
            const results = await searchGames(searchQuery);
            res.json({ results });
        } catch (error) {
            console.error('Error searching games:', error);
            res.status(500).json({ error: 'Error searching games.' });
        }
    })
);



// Function to search games based on a query using Supabase
async function searchGames(searchTerm) {
    try {
        // 🔁 Call the Postgres RPC instead of .ilike()
        const { data, error } = await supabase
            .rpc('search_games_unaccent', { search_term: searchTerm });

        // Preserve your existing error check
        if (error) {
            throw new Error('Error searching games (unaccent): ' + error.message);
        }

        // Map to your API shape
        const results = data.map(game => ({
            GameId: game.gameid,
            Name: game.name,
            CoverArt: game.coverart,
            Console: game.console,
        }));

        return results;
    } catch (error) {
        console.error('Error searching games:', error);
        throw error;       // Let the route handler catch & respond
    }
}







// Add wishlist game to wishlist
app.post('/api/add-to-wishlist/:userId/:gameId', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
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
app.get('/api/mywishlist/:userId', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
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
app.delete('/api/removewishlist/:userId/:gameId', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
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
app.get('/api/mycollection/:userId', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
    const userId = req.params.userId;
    try {
        const results = await getCollectionItems(userId);
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
        .select('gameinfo(gameid, name, coverart, console)')
        .eq('userid', userId);

    if (error) {
        console.error('Error fetching collection items:', error.message);
        throw error;
    }

    // No need to convert coverArt to base64 if it's already stored as a string
    return data.map(item => ({
        GameId: item.gameinfo.gameid,
        Name: item.gameinfo.name,
        CoverArt: item.gameinfo.coverart,  // Directly use the coverArt
        Console: item.gameinfo.console,
    }));
}


// Navigation from Search to check if the game details already exist for the game in collection
app.get('/api/check-gamedetails/:userId/:gameId', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
    const { userId, gameId } = req.params;

    try {
        const result = await checkGameDetails(userId, gameId);

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
app.get('/api/game-info/:gameId', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
    const gameId = req.params.gameId;

    try {
        // Fetch game details based on gameId
        const gameDetails = await getGameDetails(gameId);

        if (gameDetails) {
            // Directly use the stored Base64 string
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
app.post('/api/add-game-details/:userId/:gameId', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
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
async function addGameDetails(userid, gameid, gameDetails) {
    const { ownership, included, checkboxes, notes, completion, review, spoiler, price, rating } = gameDetails.gameDetails;

    // Assuming 'checkboxes' is an array of checkbox values, convert to a string
    const checkboxesString = Array.isArray(checkboxes) ? checkboxes.join(', ') : checkboxes;

    // Convert boolean values to 0 or 1
    const spoilerValue = spoiler ? 1 : 0;

    try {
        // Insert game details
        const { data: gameDetailsData, error: gameDetailsError } = await supabase
            .from('gamedetails')
            .insert({
                ownership: ownership,
                included: included,
                condition: checkboxesString,
                notes: notes,
                completion: completion,
                review: review,
                spoiler: spoilerValue,
                price: price,
                rating: rating
            })
            .select('gamedetailsid')
            .single();

        if (gameDetailsError) {
            console.error('Error adding game details:', gameDetailsError);
            throw new Error(`Error adding game details: ${gameDetailsError.message}`);
        }

        const { gamedetailsid } = gameDetailsData;

        // Insert into vgcollection
        const { data: vgCollectionData, error: vgCollectionError } = await supabase
            .from('vgcollection')
            .insert({
                userid: userid,
                gameid: gameid,
                gamedetailsid: gamedetailsid
            })
            .select();  // Add select() to return inserted data

        if (vgCollectionError) {
            console.error('Error adding VGCollection record:', vgCollectionError);
            throw new Error(`Error adding VGCollection record: ${vgCollectionError.message}`);
        }

        return vgCollectionData !== null;
    } catch (error) {
        console.error('Error in addGameDetails function:', error);
        throw error;
    }
}






// Remove a game from the collection
app.delete('/api/removecollection/:userId/:gameId', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
    const userId = req.params.userId;
    const gameId = req.params.gameId;

    try {
        // Fetch collection data for the game
        const { data: collectionData, error: collectionError } = await supabase
            .from('vgcollection')
            .select('collectionid, gamedetailsid')
            .eq('userid', userId)
            .eq('gameid', gameId)
            .single();

        if (collectionError) {
            console.error('Error fetching collection data:', collectionError.message);
            return res.status(500).json({ error: 'Error fetching collection data' });
        }

        if (collectionData) {
            const vgCollectionId = collectionData.collectionid;
            const gameDetailsId = collectionData.gamedetailsid;

            console.log(`Fetched collection data: VGCollectionId=${vgCollectionId}, GameDetailsId=${gameDetailsId}`);

            if (vgCollectionId && gameDetailsId) {
                // Remove the game from VGCollection
                await removeGameFromCollection(userId, gameId);

                // Remove the associated GameDetails record
                await removeGameDetails(gameDetailsId);

                res.status(200).json({ message: 'Game removed successfully' });
            } else {
                console.warn('No valid VGCollectionId or GameDetailsId found');
                res.status(404).json({ error: 'Invalid collection data' });
            }
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
    if (!gameDetailsId) {
        console.error('Invalid gameDetailsId:', gameDetailsId);
        throw new Error('Invalid gameDetailsId');
    }

    const { error } = await supabase
        .from('gamedetails')
        .delete()
        .eq('gamedetailsid', gameDetailsId);

    if (error) {
        console.error('Error removing game details:', error.message);
        throw error;
    }
}






app.get('/api/get-game-details/:userId/:gameId', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
    const userId = req.params.userId;
    const gameId = req.params.gameId;

    console.log("Fetching game details for user:", userId, "and game:", gameId);

    try {
        // Fetch game details based on gameId for a specific user using Supabase
        const { data, error } = await supabase
            .from('vgcollection')
            .select(`
                gameinfo (
                    gameid,
                    name,
                    coverart,
                    console
                ),
                gamedetails (
                    ownership,
                    included,
                    condition,
                    notes,
                    price,
                    completion,
                    rating,
                    review,
                    spoiler
                )
            `)
            .eq('gameid', gameId)
            .eq('userid', userId)
            .single();

        if (error) {
            console.error('Error fetching game details:', error.message);
            return res.status(500).json({ error: 'Error fetching game details.' });
        }

        if (data) {
            console.log('This is the condition before: ', data.gamedetails.condition);
            //Put condition string back into an array
            if (data.gamedetails.condition) {
                data.gamedetails.condition = data.gamedetails.condition.split(',').map(item => item.trim());
            }
            console.log('This is the condition after: ', data.gamedetails.condition);

            // No need to convert CoverArt to Base64, it's already in Base64
            console.log("Fetched game details:", data); // Log the fetched data for debugging
            res.json({ gameDetails: data });
        } else {
            res.status(404).json({ error: 'Game details not found' });
        }
    } catch (error) {
        console.error('Error fetching game details:', error.message);
        res.status(500).json({ error: 'Error fetching game details.' });
    }
}));


// Add this new route to your server code
app.put('/api/edit-game-details/:userId/:gameId', passport.authenticate('jwt', { session: false }), async (req, res) => {
    const userId = parseInt(req.params.userId, 10);
    const gameId = parseInt(req.params.gameId, 10);
    const gameDetails = req.body;

    try {
        // Call the editGameDetails function with the provided parameters
        const success = await editGameDetails(userId, gameId, gameDetails);

        if (success) {
            res.status(200).json({ message: 'Game details updated successfully' });
        } else {
            res.status(500).json({ message: 'Failed to update game details' });
        }
    } catch (error) {
        console.error('Error updating game details:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Function to update game details
async function editGameDetails(userId, gameId, gameDetails) {
    const { ownership, included, checkboxes, notes, gameCompletion: completion, review, spoilerWarning: spoiler, pricePaid: price, rating } = gameDetails;

    // Convert checkboxes to a string to store in the database
    const checkboxesString = Array.isArray(checkboxes) ? checkboxes.join(',') : checkboxes;
    const spoilerValue = spoiler ? 1 : 0;

    try {
        // Retrieve gamedetailsid from vgcollection
        const { data: vgcollectionData, error: vgcollectionError } = await supabase
            .from('vgcollection')
            .select('gamedetailsid')
            .eq('userid', userId)
            .eq('gameid', gameId)
            .single();

        if (vgcollectionError || !vgcollectionData) {
            console.error('Error fetching gamedetailsid:', vgcollectionError?.message || 'No data found');
            return false;
        }

        const gamedetailsid = vgcollectionData.gamedetailsid;

        // Update the gamedetails
        const { data: updateData, error: updateError } = await supabase
            .from('gamedetails')
            .update({
                ownership,
                included,
                condition: checkboxesString,
                notes,
                completion,
                review,
                spoiler: spoilerValue,
                price,
                rating
            })
            .eq('gamedetailsid', gamedetailsid);

        if (updateError) {
            console.error('Error updating game details:', updateError.message);
            return false;
        }

        console.log('Update result:', updateData);

        // Check if the update operation reported any affected rows or returned data
        if (updateData !== null) {
            return true;
        } else {
            return true;  // Treat as successful if no error was reported
        }
    } catch (error) {
        console.error('Unexpected error updating game details:', error.message);
        return false;
    }
}



app.get('/api/reports/:reportType', passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        console.log("Received request for report type:", req.params.reportType);
        const reportTypes = req.params.reportType.split(','); // Split the report types
        const results = {};

        // Process each report type
        for (const reportType of reportTypes) {
            console.log(`Processing report type: ${reportType}`);

            // Total Users
            if (reportType === 'TotalUsers') {
                const { data: totalUsersData, error: totalUsersError } = await supabase
                    .from('useraccount')
                    .select('userid', { count: 'exact' });

                if (totalUsersError) throw totalUsersError;
                results.totalUsers = { count: totalUsersData.length };
            }

            // Total Collections
            if (reportType === 'TotalCollections') {
                const { data: totalCollectionsData, error: totalCollectionsError } = await supabase
                    .from('vgcollection')
                    .select('collectionid', { count: 'exact' });

                if (totalCollectionsError) throw totalCollectionsError;
                results.totalCollections = { count: totalCollectionsData.length };
            }

            // Most Collected Game
            if (reportType === 'MostCollectedGame') {
                const { data: vgCollectionData, error: vgCollectionError } = await supabase
                    .from('vgcollection')
                    .select('gameid');

                if (vgCollectionError) throw vgCollectionError;

                // Count occurrences of each gameid
                const gameCount = {};
                vgCollectionData.forEach(({ gameid }) => {
                    gameCount[gameid] = (gameCount[gameid] || 0) + 1;
                });

                // Find the gameid with the highest count
                let mostCollectedGameId = null;
                let maxCount = 0;
                for (const gameid in gameCount) {
                    if (gameCount[gameid] > maxCount) {
                        maxCount = gameCount[gameid];
                        mostCollectedGameId = gameid;
                    }
                }

                if (mostCollectedGameId) {
                    const { data: mostCollectedGame, error: mostCollectedGameError } = await supabase
                        .from('gameinfo')
                        .select('*')
                        .eq('gameid', mostCollectedGameId)
                        .single();

                    if (mostCollectedGameError) throw mostCollectedGameError;
                    results.mostCollectedGame = {
                        ...mostCollectedGame,
                        count: maxCount
                    };
                } else {
                    results.mostCollectedGame = { count: 0 };
                }
            }

            // Highest Reviewed Game
            if (reportType === 'HighestReviewedGame') {
                // Step 1: Fetch the highest rating from gamedetails
                const { data: highestRatingData, error: highestRatingError } = await supabase
                    .from('gamedetails')
                    .select('rating, gamedetailsid')
                    .order('rating', { ascending: false })
                    .limit(1);

                if (highestRatingError) throw highestRatingError;

                // Extract the highest rating and corresponding gamedetailsid
                const highestRating = highestRatingData[0]?.rating;
                const highestGamedetailsId = highestRatingData[0]?.gamedetailsid;

                if (highestGamedetailsId) {
                    // Step 2: Find the gameid related to the highest-rated gamedetailsid
                    const { data: gameIdData, error: gameIdError } = await supabase
                        .from('vgcollection')
                        .select('gameid')
                        .eq('gamedetailsid', highestGamedetailsId)
                        .limit(1);

                    if (gameIdError) throw gameIdError;

                    const gameId = gameIdData[0]?.gameid;

                    if (gameId) {
                        // Step 3: Fetch the game details from gameinfo using gameid
                        const { data: gameInfoData, error: gameInfoError } = await supabase
                            .from('gameinfo')
                            .select('*')
                            .eq('gameid', gameId)
                            .single();

                        if (gameInfoError) throw gameInfoError;

                        // Combine the rating with the game info
                        results.highestReviewedGame = {
                            ...gameInfoData,
                            rating: highestRating
                        };
                    } else {
                        results.highestReviewedGame = { name: 'N/A', rating: 'N/A' };  // Default if no game found
                    }
                } else {
                    results.highestReviewedGame = { name: 'N/A', rating: 'N/A' };  // Default if no rating found
                }
            }



            // Most Wanted Game
            if (reportType === 'MostWantedGame') {
                // Fetch all wishlist entries
                const { data: wishlistData, error: wishlistError } = await supabase
                    .from('vgwishlist')
                    .select('gameid');

                if (wishlistError) throw wishlistError;

                // Count occurrences of each gameid
                const gameCount = {};
                wishlistData.forEach(({ gameid }) => {
                    gameCount[gameid] = (gameCount[gameid] || 0) + 1;
                });

                // Find the gameid with the highest count
                let mostWantedGameId = null;
                let maxCount = 0;
                for (const gameid in gameCount) {
                    if (gameCount[gameid] > maxCount) {
                        maxCount = gameCount[gameid];
                        mostWantedGameId = gameid;
                    }
                }

                if (mostWantedGameId) {
                    // Fetch details of the most wanted game
                    const { data: mostWantedGame, error: mostWantedGameError } = await supabase
                        .from('gameinfo')
                        .select('*')
                        .eq('gameid', mostWantedGameId)
                        .single();

                    if (mostWantedGameError) throw mostWantedGameError;
                    results.mostWantedGame = {
                        ...mostWantedGame,
                        count: maxCount  // Include the count in the response
                    };
                } else {
                    results.mostWantedGame = { count: 0 };  // Default to 0 if no game found
                }
            }


            // Total Wishlists
            if (reportType === 'TotalWishlists') {
                const { data: totalWishlistsData, error: totalWishlistsError } = await supabase
                    .from('vgwishlist')
                    .select('*', { count: 'exact' });

                if (totalWishlistsError) throw totalWishlistsError;
                results.totalWishlists = { count: totalWishlistsData.length };
            }
        }

        res.json(results);
    } catch (error) {
        console.error('Error fetching reports:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});




app.put('/api/update-username/:userId', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { newUsername } = req.body;

    try {
        // Update the username in the Supabase UserAccount table
        const { data, error } = await supabase
            .from('useraccount')
            .update({ username: newUsername })
            .eq('userid', parseInt(userId)); // Ensure userId is the correct type

        // Log the data and error for debugging
        console.log('Update Data:', data);
        console.log('Update Error:', error);

        if (error) {
            throw error;
        }

        // If `data` is null, but no error, assume success
        if (data === null) {
            res.status(200).json({ message: 'Username updated successfully' });
        } else {
            res.status(404).json({ error: 'Username update has an error' });
        }
    } catch (error) {
        console.error('Error updating username:', error.message);
        res.status(500).json({ error: 'Error updating username' });
    }
}));






// Check if username exists
app.get('/api/check-username/:username', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
    const { username } = req.params;

    try {
        const { data, error } = await supabase
            .from('useraccount')
            .select('username')
            .eq('username', username);

        if (error) throw error;

        const exists = data.length > 0;
        res.json({ exists });
    } catch (error) {
        console.error('Error checking username:', error.message);
        res.status(500).json({ error: 'Error checking username' });
    }
}));


// Update password
app.put('/api/update-password/:userId', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { newPassword } = req.body;

    try {
        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the password in the Supabase UserAccount table
        const { data, error } = await supabase
            .from('useraccount')
            .update({ password: hashedPassword })
            .eq('userid', userId);

        if (error) throw error;

        if (data === null) {
            res.status(200).json({ message: 'Password updated successfully' });
        } else {
            res.status(404).json({ error: 'User not found or password unchanged' });
        }
    } catch (error) {
        console.error('Error updating password:', error.message);
        res.status(500).json({ error: 'Error updating password' });
    }
}));


// Update email
app.put('/api/update-email/:userId', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { newEmail } = req.body;

    try {
        // Update the email in the Supabase UserAccount table
        const { data, error } = await supabase
            .from('useraccount')
            .update({ email: newEmail })
            .eq('userid', userId);

        if (error) throw error;

        if (data === null) {
            res.status(200).json({ message: 'Email updated successfully' });
        } else {
            res.status(404).json({ error: 'User not found or email unchanged' });
        }
    } catch (error) {
        console.error('Error updating email:', error.message);
        res.status(500).json({ error: 'Error updating email' });
    }
}));


// Check if email exists
app.get('/api/check-email/:email', passport.authenticate('jwt', { session: false }), asyncHandler(async (req, res) => {
    const { email } = req.params;

    try {
        const { data, error } = await supabase
            .from('useraccount')
            .select('email')
            .eq('email', email);

        if (error) throw error;

        const exists = data.length > 0;
        res.json({ exists });
    } catch (error) {
        console.error('Error checking email:', error.message);
        res.status(500).json({ error: 'Error checking email' });
    }
}));


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



