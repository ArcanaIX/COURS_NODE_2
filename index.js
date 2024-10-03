import chalk from "chalk";
import http from "http";
import fs from "fs";
import bcrypt from "bcrypt";

const saltRound = 10;

function crypt(text, saltRounds) {
    let res = "";
    bcrypt.hashSync(text, saltRounds, (err, hash) => {
        if (err) {
            // Handle error
            return;
        }

        // Hashing successful, 'hash' contains the hashed password
        console.log('Hashed password:', hash);
        res = hash;
    });
    return res;
}

http.createServer((req, res) => {

    switch (req.url) {
        case "/" :
            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(fs.readFileSync("./frontend/index.html"));
            break;

        case "/user/connexion" :
            let body = [];
            req.on("data", (chunk) => {
                body.push(chunk);
            });

            req.on("end", () => {
                const credentials = Buffer.concat(body).toString("utf8");
                const user = JSON.parse(credentials);
                bcrypt.hash(user.password, saltRound, (err, hash) => {
                    if (err) {}
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({
                        "credential" : hash
                    }));
                })

            });
            break;
    }

}).listen(3000, () => {
    console.log(chalk.blue(`Server started on port 3000!`));
});