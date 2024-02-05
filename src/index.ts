import app from "./app";
import dotenv from "dotenv";
import connectDB from "./database/index";

const port = process.env.PORT || 5000;

dotenv.config({
  path: "./env",
});
connectDB()
  .then(() => {
    app.on("error", () => {
      console.log("Error running server");
    });
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  })
  .catch((error) => {
    console.log("Error:", error.message);
    process.exit(1);
  });
