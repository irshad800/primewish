const { error } = require("console")
const experess = require("express")
const app = experess()
const mongoose = require("mongoose")
 const { url } = require("inspector")
const { urlencoded } = require("body-parser")
const cors = require('cors');
const authRouter = require("./routes/auth_routes")
const path = require("path")


app.use(cors()); 

require ('dotenv').config();

mongoose.connect(process.env.MONGODB_URI).then(() => {
    console.log("Database Connected");
}).catch((error) => {
    console.log(error)
})
app.use(experess.json())
app.use(experess.urlencoded({
    extended: true  
}))

app.use("/api/auth",authRouter)




app.use(experess.static(path.join(__dirname, 'public')));


//routing structure
//syntax:app.method(path,handler)=>resource.send(response)
app.get("/", (req, res) => {
    res.send("hello")
}
)
app.get("/add", (req, res) => {
    res.send("hi")
}
)
app.get("/a", (req, res) => {
    res.send("a")
}
)
app.get("/b", (req, res) => {
    res.send("b")
}
)

app.use(cors)
app.listen(process.env.PORT, () => {
    console.log('server started')
})