package com.ewallet.resource.utils.convert;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;
import java.util.stream.Collectors;

public class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

	public static final String REALM_ACCESS = "realm_access";
	public static final String RESOURCE_ACCESS = "resource_access";
	public static final String ROLES = "roles";
	public static final String ROLE_PREFIX = "ROLE_";

	@SuppressWarnings("unchecked")
	@Override
	public Collection<GrantedAuthority> convert(final Jwt jwt) {
		Collection<GrantedAuthority> roles = new HashSet<>();
		if(jwt.getClaims().containsKey(REALM_ACCESS)){
			//
			final Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get(REALM_ACCESS);
			roles.addAll(((List<String>)realmAccess.get(ROLES)).stream()
					.map(roleName -> ROLE_PREFIX + roleName)
					.map(SimpleGrantedAuthority::new)
					.collect(Collectors.toList()));
		}
		if(jwt.getClaims().containsKey(RESOURCE_ACCESS)){
			//
			final Map<Object, Object> resourceAccess = (Map<Object, Object>) jwt.getClaims().get(RESOURCE_ACCESS);
			Set<Object> keyResource = resourceAccess.keySet();
			for (Object key : keyResource) {
				Map<String, Object> listRole = (Map<String, Object>)resourceAccess.get(key);
				roles.addAll(((List<String>)listRole.get(ROLES)).stream()
						.map(roleName -> ROLE_PREFIX + roleName)
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toList()));
			}
		}

		return roles;
	}
}
