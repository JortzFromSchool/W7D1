class User < ApplicationRecord
  validates :username, :session_token, uniqueness: true, presence: true
  validates :password_digest, presence: true
  validates :password, length: { minimum: 6, allow_nil: true }


  attr_reader :password

  def password=(password)
    @password = password
    self.password_digest = BCrypt::Password.create(password)
  end

  def is_password?(password)
    password_object = BCrypt::Password.new(self.password_digest)
    password_object.is_password?(password)
  end

  def reset_session_token!
    self.session_token = SecureRandom::urlsafe_base64
    self.save!
  end
end
