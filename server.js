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
app.post(
    '/register',
    asyncHandler(async (req, res) => {
        const { username, email, password, admin } = req.body;

        // 1) Check for existing email
        const { data: existing, error: existErr } = await supabase
            .from('useraccount')
            .select('email')
            .eq('email', email);
        if (existErr) throw existErr;
        if (existing.length) {
            return res.status(400).json({ error: 'Email in use.' });
        }

        // 2) Hash password
        const hashed = await bcrypt.hash(password, 10);

        // 3) Handle avatar upload if provided
        let avatar_url = null;
        if (req.files?.avatar) {
            const { avatar } = req.files;
            // this path is *inside* the bucket
            const objectPath = `${Date.now()}_${avatar.name}`;

            // 1️⃣ Upload to the 'avatars' bucket
            const { data: uploadData, error: uploadErr } = await supabase
                .storage
                .from('avatars')
                .upload(objectPath, avatar.data, {
                    contentType: avatar.mimetype,
                    upsert: false
                });
            if (uploadErr) throw uploadErr;

            // 2️⃣ Grab the *public* URL
            const { data: urlData, error: urlErr } = supabase
                .storage
                .from('avatars')
                .getPublicUrl(objectPath);
            if (urlErr) throw urlErr;

            avatar_url = urlData.publicUrl;
        }

        // 4) Create the user row (including avatar_url)
        const newRow = {
            username,
            email,
            password: hashed,
            admin: admin ? 1 : 0,
            avatar_url
        };
        const { data: inserted, error: insertErr } = await supabase
            .from('useraccount')
            .insert(newRow)
            .select('*')
            .single();
        if (insertErr) throw insertErr;

        // 5) Generate tokens & set refresh cookie
        const accessToken = generateAccessToken(inserted);
        const refreshToken = generateRefreshToken(inserted);
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
            path: '/',
        });

        // 6) Return the safe user object
        const safeUser = {
            userid: inserted.userid,
            username: inserted.username,
            email: inserted.email,
            admin: inserted.admin,
            avatar: inserted.avatar_url
        };
        res.status(201).json({
            accessToken,
            refreshToken,
            user: safeUser
        });
    })
);


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
app.post(
    '/add-game-to-database',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const { Name, Consoles } = req.body;             // <-- now Consoles is a JSON string
        const consoleIds = JSON.parse(Consoles);         // e.g. [1, 5, 12]

        if (!req.files?.CoverArt) {
            return res.status(400).json({ error: 'CoverArt is required.' });
        }

        // 1) Insert into gameinfo (without console column)
        const coverArtBase64 = req.files.CoverArt.data.toString('base64');
        const { data: inserted, error: insertError } = await supabase
            .from('gameinfo')
            .insert([{ name: Name, coverart: coverArtBase64 }])
            .select('gameid')
            .single();

        if (insertError) {
            console.error('Error inserting gameinfo:', insertError.message);
            return res.status(500).json({ error: 'Error adding game.', details: insertError.message });
        }
        const gameid = inserted.gameid;

        // 2) Insert into gameinfo_console for each platform
        const links = consoleIds.map((cid) => ({
            gameid,
            consoleid: cid,
        }));
        const { error: linkError } = await supabase
            .from('gameinfo_console')
            .insert(links);

        if (linkError) {
            console.error('Error linking consoles:', linkError.message);
            return res
                .status(500)
                .json({ error: 'Game added but failed to link consoles.', details: linkError.message });
        }

        res.status(200).json({ message: 'Game added successfully.' });
    })
);



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
        // 1) First, get your basic game rows via your existing RPC
        const { data: games, error: rpcError } = await supabase
            .rpc('search_games_unaccent', { search_term: searchTerm });
        if (rpcError) {
            throw new Error('Error searching games (unaccent): ' + rpcError.message);
        }

        // If no games, early‐return []
        if (!games || games.length === 0) return [];

        // 2) Next, fetch all consoles for those GameIds in one go
        const gameIds = games.map((g) => g.gameid);
        const { data: consoleRows, error: consErr } = await supabase
            .from('gameinfo_console')
            .select('gameid, console:console ( consoleid, name )')
            .in('gameid', gameIds);
        if (consErr) throw consErr;

        // 3) Build a map: gameid → [ {consoleid, name}, … ]
        const consolesByGame = consoleRows.reduce((map, row) => {
            if (!map[row.gameid]) map[row.gameid] = [];
            map[row.gameid].push(row.console);
            return map;
        }, {});

        // 4) Finally, merge consoles into your result shape
        return games.map((g) => ({
            GameId: g.gameid,
            Name: g.name,
            CoverArt: g.coverart,
            // either the joined array, or empty if none
            Consoles: consolesByGame[g.gameid] || []
        }));
    } catch (error) {
        console.error('Error searching games with consoles:', error);
        throw error;
    }
}

//Check if a game is already in the wishlist
app.get(
    '/api/check-wishlist/:userId/:gameId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const userId = Number(req.params.userId);
        const gameId = Number(req.params.gameId);

        // look for an entry in vgwishlist
        const { data, error } = await supabase
            .from('vgwishlist')
            .select('userid, gameid')
            .eq('userid', userId)
            .eq('gameid', gameId);

        if (error) {
            console.error('Error checking wishlist:', error.message);
            return res.status(500).json({ error: 'Error checking wishlist.' });
        }

        return res.json({ hasWishlist: Array.isArray(data) && data.length > 0 });
    })
);



// Add wishlist game to wishlist
app.post(
    '/api/add-game-wishlist/:userId/:gameId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const userId = Number(req.params.userId);
        const gameId = Number(req.params.gameId);
        const { consoleIds } = req.body;      // array of ints

        if (!Array.isArray(consoleIds) || consoleIds.length === 0) {
            return res.status(400).json({ error: 'Must select at least one platform' });
        }

        // 1) insert into vgwishlist
        const { data: wl, error: wErr } = await supabase
            .from('vgwishlist')
            .insert({ userid: userId, gameid: gameId })
            .select('wishlistid')
            .single();
        if (wErr) {
            console.error('Error creating wishlist record:', wErr);
            return res.status(500).json({ error: 'Error creating wishlist' });
        }

        // 2) insert join rows
        const rows = consoleIds.map(consoleid => ({
            wishlistid: wl.wishlistid,
            consoleid
        }));
        const { error: wcErr } = await supabase
            .from('vgwishlist_console')
            .insert(rows);
        if (wcErr) {
            console.error('Error inserting wishlist consoles:', wcErr);
            return res.status(500).json({ error: 'Error saving platforms' });
        }

        res.json({ message: 'Added to wishlist!' });
    })
);

// Route to retrieve wishlist items for MyWishlist page
app.get(
    '/api/mywishlist/:userId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const userId = Number(req.params.userId);

        try {
            // 1️⃣ Get the user’s saved wishlist rows (wishlistid + gameid)
            const { data: saved, error: sErr } = await supabase
                .from('vgwishlist')
                .select('wishlistid, gameid')
                .eq('userid', userId);
            if (sErr) {
                console.error('Error fetching vgwishlist rows:', sErr.message);
                return res.status(500).json({ error: 'Error fetching wishlist.' });
            }
            if (!saved.length) {
                return res.json({ results: [] });
            }

            // 2️⃣ Pull basic game info
            const gameIds = saved.map((r) => r.gameid);
            const { data: games, error: gErr } = await supabase
                .from('gameinfo')
                .select('gameid, name, coverart')
                .in('gameid', gameIds);
            if (gErr) {
                console.error('Error fetching gameinfo:', gErr.message);
                return res.status(500).json({ error: 'Error fetching games.' });
            }

            // 3️⃣ Pull only the consoles the user picked for each wishlist row
            const wlIds = saved.map((r) => r.wishlistid);
            const { data: consoleRows, error: cErr } = await supabase
                .from('vgwishlist_console')
                .select('wishlistid, console:console ( consoleid, name )')
                .in('wishlistid', wlIds);
            if (cErr) {
                console.error('Error fetching wishlist consoles:', cErr.message);
                return res.status(500).json({ error: 'Error fetching consoles.' });
            }

            // 4️⃣ Build a lookup: wishlistid → [ {consoleid,name}, … ]
            const consolesByWl = consoleRows.reduce((map, row) => {
                map[row.wishlistid] = map[row.wishlistid] || [];
                map[row.wishlistid].push(row.console);
                return map;
            }, {});

            // 5️⃣ Assemble final results
            const results = saved.map(({ wishlistid, gameid }) => {
                const g = games.find((x) => x.gameid === gameid) || {};
                return {
                    GameId: g.gameid,
                    Name: g.name,
                    CoverArt: g.coverart,
                    Consoles: (consolesByWl[wishlistid] || []).sort((a, b) =>
                        a.name.localeCompare(b.name)
                    ),
                };
            });

            res.json({ results });
        } catch (err) {
            console.error('Unexpected error in /api/mywishlist:', err.message);
            res.status(500).json({ error: 'Internal server error fetching wishlist.' });
        }
    })
);

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

// GET the consoles for a wishlist item
app.get(
    '/api/get-wishlist-details/:userId/:gameId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const userId = Number(req.params.userId);
        const gameId = Number(req.params.gameId);

        // 1) First grab the wishlistid
        const { data: wl, error: wlErr } = await supabase
            .from('vgwishlist')
            .select('wishlistid')
            .eq('userid', userId)
            .eq('gameid', gameId)
            .single();

        if (wlErr || !wl) {
            console.error('Error fetching wishlist parent:', wlErr);
            return res.status(404).json({ error: 'Wishlist item not found.' });
        }

        // 2) Now fetch child consoles for that wishlistid
        const { data: rows, error } = await supabase
            .from('vgwishlist_console')
            .select('console ( consoleid, name )')
            .eq('wishlistid', wl.wishlistid);

        if (error) {
            console.error('Error fetching wishlist consoles:', error);
            return res.status(500).json({ error: 'Error fetching wishlist consoles.' });
        }

        // unwrap and return
        const consoles = (rows || []).map(r => r.console);
        res.json({ consoles });
    })
);

// PUT update consoles on a wishlist entry
app.put(
    '/api/edit-wishlist/:userId/:gameId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const userId = Number(req.params.userId);
        const gameId = Number(req.params.gameId);
        const { consoleIds } = req.body;

        // 1) Fetch the wishlistid first
        const { data: wl, error: wlErr } = await supabase
            .from('vgwishlist')
            .select('wishlistid')
            .eq('userid', userId)
            .eq('gameid', gameId)
            .single();
        if (wlErr || !wl) {
            console.error('Error fetching wishlist parent:', wlErr);
            return res.status(404).json({ error: 'Wishlist item not found.' });
        }
        const wishlistid = wl.wishlistid;

        // 2) Delete old child links by wishlistid
        const { error: delErr } = await supabase
            .from('vgwishlist_console')
            .delete()
            .eq('wishlistid', wishlistid);
        if (delErr) {
            console.error('Error deleting old consoles:', delErr);
            throw delErr;
        }

        // 3) Insert new ones
        if (Array.isArray(consoleIds) && consoleIds.length) {
            const rows = consoleIds.map(cid => ({
                wishlistid,
                consoleid: cid
            }));
            const { error: insErr } = await supabase
                .from('vgwishlist_console')
                .insert(rows);
            if (insErr) {
                console.error('Error inserting new consoles:', insErr);
                throw insErr;
            }
        }

        res.status(200).json({ message: 'Wishlist updated successfully' });
    })
);



// Route to retrieve collection items for MyCollection page
app.get(
    '/api/mycollection/:userId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const userId = Number(req.params.userId);

        try {
            // 1️⃣ Pull the user’s saved games (collectionid + gameid)
            const { data: saved, error: sErr } = await supabase
                .from('vgcollection')
                .select('collectionid, gameid')
                .eq('userid', userId);
            if (sErr) {
                console.error('Error fetching vgcollection rows:', sErr);
                return res.status(500).json({ error: 'Error fetching collection rows.' });
            }
            if (saved.length === 0) {
                return res.json({ results: [] });
            }

            // Build two helper arrays:
            const gameIds = saved.map((r) => r.gameid);
            const vcIds = saved.map((r) => r.collectionid);

            // 2️⃣ Fetch base info from gameinfo
            const { data: games, error: gErr } = await supabase
                .from('gameinfo')
                .select('gameid, name, coverart')
                .in('gameid', gameIds);
            if (gErr) {
                console.error('Error fetching gameinfo:', gErr);
                return res.status(500).json({ error: 'Error fetching games.' });
            }

            // 3️⃣ Fetch only the user‐picked consoles from vgcollection_console
            const { data: ccRows, error: ccErr } = await supabase
                .from('vgcollection_console')
                .select('collectionid, console:console ( consoleid, name )')
                .in('collectionid', vcIds);
            if (ccErr) {
                console.error('Error fetching user consoles:', ccErr);
                return res.status(500).json({ error: 'Error fetching consoles.' });
            }

            // 4️⃣ Build a lookup: vgcollectionid → [ {consoleid,name}, … ]
            const consolesByVg = ccRows.reduce((map, row) => {
                map[row.collectionid] = map[row.collectionid] || [];
                map[row.collectionid].push(row.console);
                return map;
            }, {});

            // 5️⃣ Assemble the final shape
            const results = saved.map(({ collectionid, gameid }) => {
                const g = games.find((x) => x.gameid === gameid) || {};
                return {
                    GameId: g.gameid,
                    Name: g.name,
                    CoverArt: g.coverart,
                    Consoles: (consolesByVg[collectionid] || [])
                        .sort((a, b) => a.name.localeCompare(b.name)),
                };
            });

            return res.json({ results });
        } catch (error) {
            console.error('Unexpected error in /api/mycollection:', error);
            return res
                .status(500)
                .json({ error: 'Internal server error fetching collection.' });
        }
    })
);


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
app.get(
    '/api/game-info/:gameId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const gameId = Number(req.params.gameId);
        // 1️⃣ Fetch the core record
        const { data: core, error: coreErr } = await supabase
            .from('gameinfo')
            .select('gameid, name, coverart')
            .eq('gameid', gameId)
            .single();
        if (coreErr || !core) {
            return res.status(404).json({ error: 'Game not found' });
        }

        // 2️⃣ Fetch its consoles via the join table
        const { data: joinRows, error: joinErr } = await supabase
            .from('gameinfo_console')
            .select('console:console ( consoleid, name )')
            .eq('gameid', gameId);
        if (joinErr) {
            console.error('Error fetching consoles for game:', joinErr);
            return res.status(500).json({ error: 'Error fetching consoles' });
        }

        // 3️⃣ Extract the console objects
        const consoles = joinRows.map((r) => r.console);

        // 4️⃣ Respond with the combined shape
        res.status(200).json({
            gameDetails: {
                gameid: core.gameid,
                name: core.name,
                coverart: core.coverart,
                consoles,            // ← your new array of { consoleid, name }
            },
        });
    })
);


// Adding Game Details + Game VGCollection Record
app.post(
    '/api/add-game-details/:userId/:gameId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const userId = Number(req.params.userId);
        const gameId = Number(req.params.gameId);

        // Pull everything directly out of req.body
        const {
            ownership,
            included,
            checkboxes,
            notes,
            completion,
            review,
            spoiler,
            price,
            rating,
            consoleIds     // ← now exists at top‐level
        } = req.body;

        try {
            // Call a helper that takes each field separately
            await insertGameDetailsAndCollection(userId, gameId, {
                ownership,
                included,
                checkboxes,
                notes,
                completion,
                review,
                spoiler,
                price,
                rating,
                consoleIds
            });

            return res.status(200).json({ message: 'Game details added successfully!' });
        } catch (error) {
            console.error('Error adding game details:', error);
            return res.status(500).json({ error: 'Error adding game details.' });
        }
    })
);

async function insertGameDetailsAndCollection(userId, gameId, data) {
    const {
        ownership,
        included,
        checkboxes,
        notes,
        completion,
        review,
        spoiler,
        price,
        rating,
        consoleIds
    } = data;

    // 1️⃣ Insert into gamedetails
    const { data: gd, error: gdErr } = await supabase
        .from('gamedetails')
        .insert({
            ownership,
            included,
            condition: Array.isArray(checkboxes) ? checkboxes.join(', ') : checkboxes,
            notes,
            completion,
            review,
            spoiler: spoiler ? 1 : 0,
            price,
            rating
        })
        .select('gamedetailsid')
        .single();
    if (gdErr) throw gdErr;

    // 2️⃣ Insert into vgcollection
    const { data: vc, error: vcErr } = await supabase
        .from('vgcollection')
        .insert({
            userid: userId,
            gameid: gameId,
            gamedetailsid: gd.gamedetailsid
        })
        .select('collectionid')
        .single();
    if (vcErr) throw vcErr;

    // 3️⃣ Insert chosen consoles
    if (Array.isArray(consoleIds) && consoleIds.length) {
        const rows = consoleIds.map((cid) => ({
            collectionid: vc.collectionid,
            consoleid: cid,
        }));
        const { error: ccErr } = await supabase
            .from('vgcollection_console')
            .insert(rows);
        if (ccErr) throw ccErr;
    }

    return true;
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


// Replace your old get-game-details with this:
app.get(
    '/api/get-game-details/:userId/:gameId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const userId = Number(req.params.userId);
        const gameId = Number(req.params.gameId);

        try {
            // Fetch the VGCollection row, join in the user-picked consoles
            const { data, error } = await supabase
                .from('vgcollection')
                .select(`
          gameinfo (
            gameid,
            name,
            coverart
          ),
          vgcollection_console (
            console (
              consoleid,
              name
            )
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
                .eq('userid', userId)
                .eq('gameid', gameId)
                .single();

            if (error) {
                console.error('Error fetching game details:', error.message);
                return res.status(500).json({ error: 'Error fetching game details.' });
            }
            if (!data) {
                return res.status(404).json({ error: 'Game details not found' });
            }

            // Pull out the consoles the user actually picked
            const consoles = (data.vgcollection_console || []).map((j) => j.console);

            // Turn the condition string back into an array
            const conditionArr = data.gamedetails.condition
                ? data.gamedetails.condition.split(',').map((c) => c.trim())
                : [];

            res.json({
                gameinfo: {
                    gameid: data.gameinfo.gameid,
                    name: data.gameinfo.name,
                    coverart: data.gameinfo.coverart,
                    consoles    // <-- user‐picked consoles only
                },
                gamedetails: {
                    ...data.gamedetails,
                    condition: conditionArr
                }
            });
        } catch (err) {
            console.error('Unexpected error fetching game details:', err.message);
            res.status(500).json({ error: 'Error fetching game details.' });
        }
    })
);


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
    const {
        ownership,
        included,
        checkboxes,
        notes,
        gameCompletion: completion,
        review,
        spoiler: spoiler,
        price,
        rating,
        consoleIds   // ← array of consoleid from client
    } = gameDetails;

    const condition = Array.isArray(checkboxes)
        ? checkboxes.join(',')
        : checkboxes;

    const spoilerValue = Number(spoiler) === 1 ? 1 : 0;

    try {
        // 1) get the vgcollection record, including its collectionid & gamedetailsid
        const { data: vgcol, error: vgcolErr } = await supabase
            .from('vgcollection')
            .select('collectionid, gamedetailsid')
            .eq('userid', userId)
            .eq('gameid', gameId)
            .single();
        if (vgcolErr || !vgcol) {
            console.error('fetch vgcollection failed:', vgcolErr);
            return false;
        }

        const { collectionid, gamedetailsid } = vgcol;

        // 2) update the gamedetails row
        const { error: updErr } = await supabase
            .from('gamedetails')
            .update({
                ownership,
                included,
                condition,
                notes,
                completion,
                review,
                spoiler: spoilerValue,
                price,
                rating
            })
            .eq('gamedetailsid', gamedetailsid);

        if (updErr) {
            console.error('update gamedetails failed:', updErr);
            return false;
        }

        // 3) wipe out the old console‐links for this collection
        const { error: delErr } = await supabase
            .from('vgcollection_console')
            .delete()
            .eq('collectionid', collectionid);
        if (delErr) {
            console.error('delete old consoles failed:', delErr);
            return false;
        }

        // 4) insert the new consoleIds
        if (Array.isArray(consoleIds) && consoleIds.length) {
            const rows = consoleIds.map(consoleid => ({
                collectionid,
                consoleid
            }));
            const { error: insErr } = await supabase
                .from('vgcollection_console')
                .insert(rows);
            if (insErr) {
                console.error('insert new consoles failed:', insErr);
                return false;
            }
        }
        return true;
    } catch (err) {
        console.error('Unexpected error in editGameDetails:', err);
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


// 1A) Update avatar (upload a new one)
app.post(
    '/api/users/avatar',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const userId = req.user.userid;

        if (!req.files?.avatar) {
            return res.status(400).json({ error: 'No file uploaded.' });
        }

        const avatar = req.files.avatar;
        const objectPath = `${Date.now()}_${avatar.name}`;

        // 1) upload to storage
        const { error: uploadErr } = await supabase
            .storage
            .from('avatars')
            .upload(objectPath, avatar.data, {
                contentType: avatar.mimetype,
                upsert: true
            });
        if (uploadErr) throw uploadErr;

        // 2) get public URL
        const { data: urlData, error: urlErr } = supabase
            .storage
            .from('avatars')
            .getPublicUrl(objectPath);
        if (urlErr) throw urlErr;

        const avatar_url = urlData.publicUrl;

        // 3) update user row
        const { data: updated, error: updateErr } = await supabase
            .from('useraccount')
            .update({ avatar_url })
            .eq('userid', userId)
            .select('userid,username,email,admin,avatar_url')
            .single();
        if (updateErr) throw updateErr;

        res.json({ avatar: updated.avatar_url });
    })
);

// 1B) Remove avatar (reset to null)
app.delete(
    '/api/users/avatar',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const userId = req.user.userid;

        // clear the column
        const { data: updated, error } = await supabase
            .from('useraccount')
            .update({ avatar_url: null })
            .eq('userid', userId)
            .select('avatar_url')
            .single();
        if (error) throw error;

        res.json({ avatar: null });
    })
);


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





//
// ───────────── USER SEARCH & FRIEND REQUESTS ─────────────
//

// 1) Search users by username (partial match), exclude yourself,
//    return flags for pending request and existing friendship.
app.get(
    '/api/users/search',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const me = req.user.userid;
        const q = req.query.q || '';

        // find matching users (excluding yourself)
        const { data: users } = await supabase
            .from('useraccount')
            .select('userid, username')
            .ilike('username', `%${q}%`)
            .neq('userid', me);

        // for each user, check friend_requests & friendships
        const results = await Promise.all(users.map(async u => {
            // pending request?
            const { count: reqCount } = await supabase
                .from('friend_requests')
                .select('*', { count: 'exact' })
                .match({ requester_id: me, target_id: u.userid });

            // already friends?
            const { count: friCount } = await supabase
                .from('friendships')
                .select('*', { count: 'exact' })
                .or(
                    `and(user_a.eq.${me},user_b.eq.${u.userid}),` +
                    `and(user_a.eq.${u.userid},user_b.eq.${me})`
                );

            return {
                id: u.userid,
                username: u.username,
                requestSent: reqCount > 0,
                isFriend: friCount > 0,
            };
        }));

        res.json(results);
    })
);

// 2) Send a friend request
app.post(
    '/api/friends/request/:targetId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const me = req.user.userid;
        const target = Number(req.params.targetId);

        await supabase
            .from('friend_requests')
            .insert({ requester_id: me, target_id: target });

        res.json({ success: true });
    })
);

// 3) Cancel a pending request
app.delete(
    '/api/friends/request/:targetId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const me = req.user.userid;
        const target = Number(req.params.targetId);

        await supabase
            .from('friend_requests')
            .delete()
            .match({ requester_id: me, target_id: target });

        res.json({ success: true });
    })
);

// 4) Accept a friend request (and upsert chat thread + return its ID)
app.post(
    '/api/friends/accept/:requesterId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const me = req.user.userid;
        const requester = Number(req.params.requesterId);

        // 1. remove the pending request
        await supabase
            .from('friend_requests')
            .delete()
            .match({ requester_id: requester, target_id: me });

        // 2. insert into friendships
        const [a, b] = [Math.min(me, requester), Math.max(me, requester)];
        await supabase
            .from('friendships')
            .insert({ user_a: a, user_b: b });

        // 3. upsert the chat_threads row and return its id
        const { data: threadData, error: threadErr } = await supabase
            .from('chat_threads')
            .upsert(
                { user_a: a, user_b: b },
                { onConflict: ['user_a', 'user_b'], returning: 'representation' }
            )
            .select('id')
            .single();

        if (threadErr || !threadData) {
            console.error('Error upserting/fetching chat thread:', threadErr);
            return res.status(500).json({ error: 'Could not determine chat thread.' });
        }

        // 4. return the threadId to the client
        res.json({ success: true, threadId: threadData.id });
    })
);



// 5) Unfriend (delete from friendships)
app.delete(
    '/api/friends/:otherId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const me = req.user.userid;
        const other = Number(req.params.otherId);

        await supabase
            .from('friendships')
            .delete()
            .or(
                `and(user_a.eq.${me},user_b.eq.${other}),` +
                `and(user_a.eq.${other},user_b.eq.${me})`
            );

        res.json({ success: true });
    })
);

// DELETE an incoming request (decline)
// current user = target, param = requester’s id
app.delete(
    '/api/friends/requests/incoming/:requesterId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const me = req.user.userid;
        const requester = Number(req.params.requesterId);

        // delete the request where requester_id = requester AND target_id = me
        const { error } = await supabase
            .from('friend_requests')
            .delete()
            .match({ requester_id: requester, target_id: me });

        if (error) {
            console.error('Error declining request:', error);
            return res.status(500).json({ error: error.message });
        }

        res.json({ success: true });
    })
);

// Server: GET /api/friends/requests/incoming
app.get(
    '/api/friends/requests/incoming',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const me = req.user.userid;
        const { data: rows, error } = await supabase
            .from('friend_requests')
            .select('requester_id')
            .eq('target_id', me);

        if (error) {
            console.error('Error fetching friend_requests:', error);
            return res.status(500).json({ error: 'Database error.' });
        }

        // ensure rows is an array
        const pending = Array.isArray(rows) ? rows : [];

        const requests = await Promise.all(pending.map(async ({ requester_id }) => {
            const { data: u, error: userErr } = await supabase
                .from('useraccount')
                .select('userid, username, avatar_url')
                .eq('userid', requester_id)
                .single();
            if (userErr) throw userErr;
            return {
                requesterId: u.userid,
                username: u.username,
                avatar: u.avatar_url
            };
        }));

        res.json(requests);
    })
);




// 11) List all your current friends + their chat thread IDs
app.get(
    '/api/friends',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const me = req.user.userid;

        // 1️⃣ Fetch all friendships involving me
        const { data: rows, error } = await supabase
            .from('friendships')
            .select('user_a, user_b')
            .or(`user_a.eq.${me},user_b.eq.${me}`);

        if (error) {
            console.error('Error fetching friendships:', error);
            return res.status(500).json({ error: 'Database error.' });
        }

        // 2️⃣ For each row, determine the other user id and lookup thread
        const friends = await Promise.all(rows.map(async ({ user_a, user_b }) => {
            const other = user_a === me ? user_b : user_a;

            // fetch their basic profile (username, avatar)
            const { data: u } = await supabase
                .from('useraccount')
                .select('userid, username, avatar_url')
                .eq('userid', other)
                .single();

            // fetch the chat thread
            const { data: threadRow } = await supabase
                .from('chat_threads')
                .select('id')
                .match({
                    user_a: Math.min(me, other),
                    user_b: Math.max(me, other)
                })
                .single();

            return {
                id: u.userid,
                username: u.username,
                avatar: u.avatar_url,
                threadId: threadRow?.id
            };
        }));

        res.json(friends);
    })
);





//
// ───────────── USER PROFILE & OTHER’S COLLECTION/WISHLIST ─────────────
//

// 6) Public user profile, plus isFriend flag & chatThreadId
app.get(
    '/api/users/:userId/profile',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const me = req.user.userid;
        const other = Number(req.params.userId);

        // 1️⃣ Fetch exactly one user row
        const { data: u, error: userErr } = await supabase
            .from('useraccount')
            .select('userid, username, avatar_url, bio')
            .eq('userid', other)
            .single();

        if (userErr) {
            console.error('Error fetching user profile:', userErr);
            return res.status(500).json({ error: 'Database error reading user.' });
        }
        if (!u) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // 2️⃣ Check friendship count
        const { count: friCount, error: friErr } = await supabase
            .from('friendships')
            .select('*', { count: 'exact' })
            .or(
                `and(user_a.eq.${me},user_b.eq.${other}),` +
                `and(user_a.eq.${other},user_b.eq.${me})`
            );

        if (friErr) {
            console.error('Error checking friendship:', friErr);
            return res.status(500).json({ error: 'Database error checking friendship.' });
        }

        // 3️⃣ Look up (or create) a chat thread
        let threadId = null;
        const { data: thread, error: threadErr } = await supabase
            .from('chat_threads')
            .select('id')
            .or(
                `and(user_a.eq.${me},user_b.eq.${other}),` +
                `and(user_a.eq.${other},user_b.eq.${me})`
            )
            .single();

        if (threadErr && threadErr.code !== 'PGRST116') { // 116 = no rows
            console.error('Error fetching chat thread:', threadErr);
            return res.status(500).json({ error: 'Database error fetching chat thread.' });
        }
        threadId = thread?.id ?? null;

        // 4️⃣ Return the combined profile
        res.json({
            id: u.userid,
            username: u.username,
            avatar: u.avatar_url,
            bio: u.bio,
            isFriend: (friCount || 0) > 0,
            chatThreadId: threadId,
        });
    })
);


// 7) Fetch another user’s collection
app.get(
    '/api/users/:userId/collection',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const other = Number(req.params.userId);

        // reuse your existing logic: fetch from vgcollection, join gameinfo and consoles
        // example simplest form:
        const { data } = await supabase
            .from('vgcollection')
            .select(`
        gameid,
        gameinfo(name, coverart),
        vgcollection_console(console (consoleid, name))
      `)
            .eq('userid', other);

        // map to the shape your frontend expects
        const results = data.map(row => ({
            GameId: row.gameid,
            Name: row.gameinfo.name,
            CoverArt: row.gameinfo.coverart,
            Consoles: row.vgcollection_console.map(c => c.console),
        }));

        res.json(results);
    })
);

// 8) Fetch another user’s wishlist
app.get(
    '/api/users/:userId/wishlist',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const other = Number(req.params.userId);

        const { data } = await supabase
            .from('vgwishlist')
            .select(`
        gameid,
        gameinfo(name, coverart),
        vgwishlist_console(console (consoleid, name))
      `)
            .eq('userid', other);

        const results = data.map(row => ({
            GameId: row.gameid,
            Name: row.gameinfo.name,
            CoverArt: row.gameinfo.coverart,
            Consoles: row.vgwishlist_console.map(c => c.console),
        }));

        res.json(results);
    })
);


// GET all incoming friend-requests for a given user (pending)
app.get(
    '/api/users/:userId/requests/incoming',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const other = Number(req.params.userId);

        // fetch requester_id rows where target = other
        const { data: rows, error } = await supabase
            .from('friend_requests')
            .select('requester_id, created_at')
            .eq('target_id', other);

        if (error) return res.status(500).json({ error: error.message });

        const incoming = await Promise.all(
            rows.map(async ({ requester_id, created_at }) => {
                const { data: u } = await supabase
                    .from('useraccount')
                    .select('userid, username, avatar_url')
                    .eq('userid', requester_id)
                    .single();
                return {
                    id: u.userid,
                    username: u.username,
                    avatar: u.avatar_url,
                    sentAt: created_at
                };
            })
        );

        res.json(incoming);
    })
);

// GET all outgoing friend-requests for a given user (pending)
app.get(
    '/api/users/:userId/requests/outgoing',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const other = Number(req.params.userId);

        // fetch target_id rows where requester = other
        const { data: rows, error } = await supabase
            .from('friend_requests')
            .select('target_id, created_at')
            .eq('requester_id', other);

        if (error) return res.status(500).json({ error: error.message });

        const outgoing = await Promise.all(
            rows.map(async ({ target_id, created_at }) => {
                const { data: u } = await supabase
                    .from('useraccount')
                    .select('userid, username, avatar_url')
                    .eq('userid', target_id)
                    .single();
                return {
                    id: u.userid,
                    username: u.username,
                    avatar: u.avatar_url,
                    sentAt: created_at
                };
            })
        );

        res.json(outgoing);
    })
);

// GET all accepted friends for a given user
app.get(
    '/api/users/:userId/friends',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const other = Number(req.params.userId);

        const { data: rows, error } = await supabase
            .from('friendships')
            .select('user_a, user_b, created_at')
            .or(`user_a.eq.${other},user_b.eq.${other}`);

        if (error) return res.status(500).json({ error: error.message });

        const friends = await Promise.all(
            rows.map(async ({ user_a, user_b, created_at }) => {
                const peer = user_a === other ? user_b : user_a;
                const { data: u } = await supabase
                    .from('useraccount')
                    .select('userid, username, avatar_url')
                    .eq('userid', peer)
                    .single();
                return {
                    id: u.userid,
                    username: u.username,
                    avatar: u.avatar_url,
                    friendedAt: created_at
                };
            })
        );

        res.json(friends);
    })
);



//
// ───────────── MESSAGING ─────────────
//

// 9) Get messages in a thread
app.get(
    '/api/messages/:threadId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const threadId = Number(req.params.threadId);
        const { data } = await supabase
            .from('chat_messages')
            .select('id, sender_id, text, sent_at, sender:sender_id(username)')
            .eq('thread_id', threadId)
            .order('sent_at', { ascending: true });

        // flatten sender username
        const messages = data.map(m => ({
            id: m.id,
            senderId: m.sender_id,
            senderName: m.sender.username,
            text: m.text,
            timestamp: m.sent_at,
        }));

        res.json(messages);
    })
);

// 10) Send a message
app.post(
    '/api/messages/:threadId',
    passport.authenticate('jwt', { session: false }),
    asyncHandler(async (req, res) => {
        const threadId = Number(req.params.threadId);
        const senderId = req.user.userid;
        const { text } = req.body;

        const { data } = await supabase
            .from('chat_messages')
            .insert([{ thread_id: threadId, sender_id: senderId, text }])
            .select('id, sender_id, text, sent_at');

        const sent = data[0];
        res.json({
            id: sent.id,
            senderId: sent.sender_id,
            senderName: req.user.username,
            text: sent.text,
            timestamp: sent.sent_at,
        });
    })
);