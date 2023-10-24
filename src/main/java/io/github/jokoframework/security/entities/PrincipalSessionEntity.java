package io.github.jokoframework.security.entities;

import jakarta.persistence.*;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Parameter;

/**
 * 
 * @author bsandoval
 *
 */
@Entity
@Table(name = "principal_session", schema = "joko_security",
	uniqueConstraints={
			@UniqueConstraint(columnNames = {"app_id", "user_id"})
	})

public class PrincipalSessionEntity {

	@GenericGenerator(
			name = "principal_session_id_seq",
			strategy = "org.hibernate.id.enhanced.SequenceStyleGenerator",
			parameters = {
					@Parameter(name = "sequence_name", value =
							"joko_security.principal_session_id_seq"),
					@Parameter(name = "increment_size", value = "1")
			}
	)
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "principal_session_id_seq")
    private Long id;

    @Column(name = "app_id")
    private String appId;
    @Column(name = "app_description")
    private String appDescription;
    @Column(name = "user_id")
    private String userId;
    @Column(name = "user_description")
    private String userDescription;
    
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getAppId() {
		return appId;
	}
	public void setAppId(String appId) {
		this.appId = appId;
	}
	public String getAppDescription() {
		return appDescription;
	}
	public void setAppDescription(String appDescription) {
		this.appDescription = appDescription;
	}
	public String getUserId() {
		return userId;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	public String getUserDescription() {
		return userDescription;
	}
	public void setUserDescription(String userDescription) {
		this.userDescription = userDescription;
	}
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("PrincipalSessionEntity [id=").append(id).append(", appId=").append(appId)
				.append(", appDescription=").append(appDescription).append(", userId=").append(userId)
				.append(", userDescription=").append(userDescription).append("]");
		return builder.toString();
	}
    
}
