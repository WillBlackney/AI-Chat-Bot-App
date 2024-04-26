import { connect, disconnect } from "mongoose";

async function connectToDatabase() {
  try {
    await connect(process.env.MONGODB_URL);
  } catch (error) {
    console.log("Connection error", error);
    throw new Error("Could not connect to mongoDB");
  }
}

async function disconnectFromDatabase() {
  try {
    await disconnect();
  } catch (error) {
    console.log("Disconnection error", error);
    throw new Error("Could not disconnect to mongoDB");
  }
}

export { connectToDatabase, disconnectFromDatabase };
