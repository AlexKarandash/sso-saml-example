package com.subbotin.saml.common;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class Users {
    private static ConcurrentMap<String, User> onlineUsers = new ConcurrentHashMap<>();

    static {
        addUser(new User("user1@example.com", "user №1"));
        addUser(new User("user2@example.com", "user №2"));
    }

    public static User getUser(String email) {
        return onlineUsers.get(email);
    }

    public static User addUser(User user) {
        return onlineUsers.put(user.getEmail(), user);
    }

    public static int getSize() {
        return onlineUsers.size();
    }
}
