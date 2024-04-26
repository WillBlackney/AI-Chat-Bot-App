import app from "./app.js";
import { connectToDatabase } from "./db/connection.js";

// Connections and listeners
const port = process.env.PORT || 5000;
connectToDatabase()
  .then(() => {
    app.listen(port), () => console.log("Server open and connected to database!");
  })
  .catch((error) => console.log(error));
