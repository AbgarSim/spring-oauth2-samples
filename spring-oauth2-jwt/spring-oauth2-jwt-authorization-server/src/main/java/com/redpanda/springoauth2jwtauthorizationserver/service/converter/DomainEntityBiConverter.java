package com.redpanda.springoauth2jwtauthorizationserver.service.converter;

public interface DomainEntityBiConverter<D, E> {

  D toDomain(E entity);

  E toEntity(D domain);

}
