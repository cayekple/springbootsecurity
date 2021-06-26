package com.cayekple.springbootsecurity.auth;

import java.util.Optional;

public interface ApplicationUserDao {

    Optional<ApplicationUser> selectionApplicationUserByUsername(String username);
}
