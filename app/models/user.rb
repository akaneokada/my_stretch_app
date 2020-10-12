class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  with_options presence: true do
    validates :nickname
    validates :gender
    validates :birthday
    validates :email,                 uniqueness: { case_sensitive: true },
                                      format: { with: /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i }
    validates :password,              confirmation: true,
                                      format: { with: /\A[a-z\d]+\z/i }
    validates :password_confirmation
  end

end
