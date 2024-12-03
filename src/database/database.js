import { Sequelize } from 'sequelize';
import 'dotenv/config';

const sequelize = new Sequelize(
    process.env.DB_DATABASE , // db name
    process.env.DB_USER , // username
    process.env.DB_PASSWORD , // pass
    {
        host: process.env.DB_HOST,
        dialect: process.env.DB_DIALECT, // or 'mysql' or 'sqlite'
        logging: console.log,

        dialectOptions: {
            ssl: {
                require: true,
                rejectUnauthorized: false,  // for self-signed certificates
            }
        }
    }
);

// Test database connection
const testConnection = async () => {
    try {
        await sequelize.authenticate();
        console.log('Connection has been established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
};

testConnection();

export default sequelize;
