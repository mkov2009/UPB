/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.Kovalak;

import java.io.IOException;
import java.sql.*;
import java.util.StringTokenizer;


public class Database {

    private static Connection conn;

    final static class MyResult {
        private final boolean first;
        private final String second;

        
        public MyResult(boolean first, String second) {
            this.first = first;
            this.second = second;
        }
        public boolean getFirst() {
            return first;
        }
        public String getSecond() {
            return second;
        }
    }

    public void createConnection(){
        try {
            Class.forName("org.h2.Driver");
            conn = DriverManager.getConnection("jdbc:h2:~/usersDB");
            Statement statement = conn.createStatement();
            statement.execute("CREATE TABLE IF NOT EXISTS users(id serial, name varchar(50), password varchar(100), salt varchar(100));");
            System.out.println("Table set.");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }
    }

    protected static MyResult add(String fileName, String text) throws IOException{ 
        if(exist(fileName, text))
            return new MyResult(false, "Meno uz existuje");

        StringTokenizer st = new StringTokenizer(text, ":");
        String name = st.nextToken();
        String hashedPassword = st.nextToken();
        String salt = st.nextToken();

        try {
            PreparedStatement preparedStatement = conn.prepareStatement("INSERT INTO users (name, password, salt) VALUES (?,?,?)");
            preparedStatement.setString(1, name); //meno
            preparedStatement.setString(2, hashedPassword); //hashovane heslo
            preparedStatement.setString(3, salt); //salt
            preparedStatement.executeUpdate();


        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }

        return new MyResult(true, "");
    }
    
    protected static MyResult find(String fileName, String text) throws IOException{
        try {
            PreparedStatement preparedStatement = conn.prepareStatement("SELECT * FROM users where name= ?");
            preparedStatement.setString(1, text);
            ResultSet resultSet = preparedStatement.executeQuery();
            while(resultSet.next()){
                String name = resultSet.getString("name");
                String password = resultSet.getString("password");
                String salt = resultSet.getString("salt");
                return new MyResult(true, name + ":" + password + ":" + salt);
            }
        } catch (SQLException throwables) {
            throwables.printStackTrace();
        }


        return new MyResult(false, "Meno sa nenaslo.");
    }
    
    protected static boolean exist(String fileName, String text) throws IOException{
        StringTokenizer st = new StringTokenizer(text, ":");
        return find(fileName, st.nextToken()).getFirst();
    }

}
